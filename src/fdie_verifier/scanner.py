"""Safe archive extraction, hashing, secret detection, and coverage-gap detection.

Highlights
----------
* ``extract_archive`` rejects zip-slip / path-traversal members (relative ``..``
  escapes, absolute paths, and symlink claims) and enforces file-count and
  uncompressed-size limits so hostile archives cannot exhaust disk or memory.
* ``scan_archive`` extracts into a private temp dir, SHA-256 hashes every file,
  detects hardcoded secrets (PEM private keys, default credentials, API tokens),
  and classifies blobs it cannot inspect — encrypted blobs, corrupt inner
  archives, unsupported firmware partition images — as unchecked regions.
* Backport awareness: OpenSSL versions found in the tree are matched against a
  small advisory table; if a backport patch marker for a CVE exists anywhere in
  the release, the CVE is classified ``LIKELY_BACKPORT_PATCHED`` instead of
  ``CONFIRMED_VULNERABLE``.
"""
from __future__ import annotations

import hashlib
import math
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .models import (
    ExtractedFile,
    Finding,
    PackageInfo,
    SecretHit,
    SecretKind,
    Severity,
    UncheckedRegion,
    UncheckedRegionKind,
    VulnerabilityStatus,
)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_FILE_COUNT = 5000
MAX_UNCOMPRESSED_TOTAL = 250 * 1024 * 1024  # 250 MiB, zip-bomb guard
MAX_CONTENT_SCAN_BYTES = 4 * 1024 * 1024  # don't regex huge files
MAX_ARCHIVE_DEPTH = 3  # nested-archive recursion limit
ENTROPY_ENCRYPTED_THRESHOLD = 7.6  # bits/byte
MIN_ENTROPY_BLOB_BYTES = 64


# ---------------------------------------------------------------------------
# Advisories (public CVE data, synthetic fixture versions)
# ---------------------------------------------------------------------------

OPENSSL_ADVISORIES: dict[str, list[tuple[str, Severity]]] = {
    "1.0.2u": [("CVE-2016-6304", Severity.HIGH), ("CVE-2016-6303", Severity.MEDIUM)],
    "1.0.2h": [("CVE-2016-2107", Severity.HIGH)],
    "1.0.2e": [("CVE-2015-3194", Severity.MEDIUM)],
    "1.0.1e": [("CVE-2014-0224", Severity.CRITICAL)],
    "1.0.1": [("CVE-2014-0160", Severity.CRITICAL)],  # Heartbleed
}

OPENSSL_VERSION_RE = re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")
BACKPORT_MARKER_RE = re.compile(rb"(?i)BACKPORT(?:ED)?[:\- ]*\(?CVE-\d{4}-\d{4,}\)?")
_BACKPORT_CVE_RE = re.compile(rb"CVE-\d{4}-\d{4,}")

ENCRYPTED_MAGICS = (
    b"AES-256-CBC",
    b"AES-128-CBC",
    b"Salted__",
    b"-----BEGIN PGP MESSAGE-----",
    b"GnuPG",
    b"encfs",
    b"LUKS",
)

UNSUPPORTED_PARTITION_MAGICS = (
    ("squashfs", b"hsqs"),
    ("jffs2", b"\x85\x19"),
    ("ubi", b"UBI#"),
    ("ext4/ext2", b"\x53\xef"),
    ("cramfs", b"\x45\x3d\xcd\x28"),
)

ENCRYPTED_EXTENSIONS = {
    ".enc", ".aes", ".gpg", ".pgp", ".blob", ".crypt",
    ".luks", ".keybox", ".sig", ".jx", ".p7m",
}

SECRET_PATTERNS: list[tuple[SecretKind, re.Pattern[bytes]]] = [
    (
        SecretKind.PEM_PRIVATE_KEY,
        re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----"),
    ),
    (
        SecretKind.DEFAULT_CREDENTIAL,
        re.compile(
            rb"(?im)(?:^|[ ,;])(?:admin|root|user|guest|support|operator)"
            rb"\s*[:/=]\s*(?:admin|root|user|guest|support|123456|password|changeme|default)"
            rb"(?=$|[\s,;])"
        ),
    ),
    (
        SecretKind.API_TOKEN,
        re.compile(
            rb"(?i)(?:api[_-]?(?:token|key)|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)"
            rb"\s*[:=]\s*[\"']?[A-Za-z0-9_\-\.]{16,}"
        ),
    ),
    (SecretKind.AWS_ACCESS_KEY, re.compile(rb"AKIA[0-9A-Z]{16}")),
    (
        SecretKind.GENERIC_SECRET,
        re.compile(rb"(?i)(?:password|passwd|pwd|secret)\s*=\s*[\"'][^\"']{8,}[\"']"),
    ),
]


class ArchiveExtractionError(Exception):
    """Raised when an archive cannot be read safely (traversal, oversize, corrupt)."""


@dataclass
class ArchiveScanResult:
    files: list[ExtractedFile] = field(default_factory=list)
    secrets: list[SecretHit] = field(default_factory=list)
    unchecked: list[UncheckedRegion] = field(default_factory=list)
    packages: list[PackageInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Hashing / entropy helpers
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def _is_textish(data: bytes) -> bool:
    return printable_ratio(data) >= 0.85


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------

def _safe_target(dest: Path, member_name: str) -> Path:
    """Resolve a member name under dest, rejecting any path traversal."""
    norm = posixpath.normpath(member_name.replace("\\", "/"))
    if norm in ("", ".", "..") or norm.startswith("../") or posixpath.isabs(norm):
        raise ArchiveExtractionError(f"path traversal blocked: {member_name!r}")
    dest_abs = dest.resolve()
    target = (dest_abs / norm).resolve()
    if target != dest_abs and not str(target).startswith(str(dest_abs) + os.sep):
        raise ArchiveExtractionError(f"zip-slip blocked: {member_name!r}")
    return target


def _extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    infos = zf.infolist()
    if len(infos) > MAX_FILE_COUNT:
        raise ArchiveExtractionError("archive contains too many entries")
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        total += info.file_size
        if total > MAX_UNCOMPRESSED_TOTAL:
            raise ArchiveExtractionError("archive exceeds uncompressed size limit")
        target = _safe_target(dest, info.filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out, length=1024 * 1024)


def _extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    members = tf.getmembers()
    if len(members) > MAX_FILE_COUNT:
        raise ArchiveExtractionError("archive contains too many entries")
    total = 0
    for member in members:
        target = _safe_target(dest, member.name)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if member.issym() or member.islnk():
            # Never materialize links: a link pointing outside dest would escape.
            continue
        if member.isreg():
            total += member.size
            if total > MAX_UNCOMPRESSED_TOTAL:
                raise ArchiveExtractionError("archive exceeds uncompressed size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
        # device / fifo / socket members are intentionally skipped


def extract_archive(archive_path: str | Path, dest: str | Path) -> list[str]:
    """Safely extract a .tar.gz/.tgz/.tar or .zip archive into ``dest``.

    Returns the sorted list of extracted relative paths. Raises
    ``ArchiveExtractionError`` for traversal attempts, oversize archives, or
    unreadable/corrupt archive content.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    path = Path(archive_path)
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                _extract_zip(zf, dest)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                _extract_tar(tf, dest)
        else:
            raise ArchiveExtractionError(f"{path} is not a readable tar/zip archive")
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveExtractionError(f"failed to read archive {path}: {exc}") from exc

    extracted: list[str] = []
    for root, _, files in os.walk(dest):
        for name in files:
            extracted.append(os.path.relpath(os.path.join(root, name), dest))
    return sorted(extracted)


def _looks_like_archive(rel: str, data: bytes) -> bool:
    lower = rel.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar", ".zip")):
        return True
    return (
        data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        or data[:2] == b"\x1f\x8b"
    )


# ---------------------------------------------------------------------------
# Blob classification (encrypted / unsupported / corrupt)
# ---------------------------------------------------------------------------

def classify_blob(rel: str, data: bytes) -> UncheckedRegion | None:
    lower = rel.lower()
    for magic in ENCRYPTED_MAGICS:
        if data.startswith(magic):
            return UncheckedRegion(
                kind=UncheckedRegionKind.ENCRYPTED,
                path=rel,
                reason=f"encryption magic {magic.decode('ascii', 'replace')!r}",
            )
    if Path(lower).suffix in ENCRYPTED_EXTENSIONS:
        return UncheckedRegion(
            kind=UncheckedRegionKind.ENCRYPTED,
            path=rel,
            reason="encrypted-blob filename extension",
        )
    for label, magic in UNSUPPORTED_PARTITION_MAGICS:
        if data.startswith(magic):
            return UncheckedRegion(
                kind=UncheckedRegionKind.UNSUPPORTED_PARTITION,
                path=rel,
                reason=f"{label} partition image (unsupported for inspection)",
            )
    if len(data) >= MIN_ENTROPY_BLOB_BYTES and not _is_textish(data):
        entropy = shannon_entropy(data)
        if entropy >= ENTROPY_ENCRYPTED_THRESHOLD:
            return UncheckedRegion(
                kind=UncheckedRegionKind.ENCRYPTED,
                path=rel,
                reason=f"high entropy ({entropy:.2f} bits/byte) — opaque/encrypted blob",
            )
    return None


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------

def detect_secrets(rel: str, data: bytes) -> list[SecretHit]:
    if len(data) > MAX_CONTENT_SCAN_BYTES or not _is_textish(data):
        return []
    hits: list[SecretHit] = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(data):
            start = m.start()
            line = data.count(b"\n", 0, start) + 1
            hits.append(
                SecretHit(
                    kind=kind,
                    path=rel,
                    line=line,
                    snippet=m.group(0).decode("ascii", "replace")[:120],
                )
            )
    return hits


# ---------------------------------------------------------------------------
# Backport / version detection
# ---------------------------------------------------------------------------

def detect_openssl_versions(data: bytes) -> list[str]:
    if not _is_textish(data):
        return []
    return [m.group(1).decode("ascii") for m in OPENSSL_VERSION_RE.finditer(data)]


def detect_backport_markers(data: bytes) -> set[str]:
    if not _is_textish(data):
        return set()
    out: set[str] = set()
    for m in BACKPORT_MARKER_RE.finditer(data):
        cve = _BACKPORT_CVE_RE.search(m.group(0))
        if cve:
            out.add(cve.group(0).decode("ascii"))
    return out


# ---------------------------------------------------------------------------
# Recursive directory scan
# ---------------------------------------------------------------------------

class _ScanContext:
    def __init__(self) -> None:
        self.files: list[ExtractedFile] = []
        self.secrets: list[SecretHit] = []
        self.unchecked: list[UncheckedRegion] = []
        self.versions: dict[str, set[str]] = {}
        self.backports: set[str] = set()

    def build_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for pkg, versions in sorted(self.versions.items()):
            for version in sorted(versions):
                for cve, severity in OPENSSL_ADVISORIES.get(version, []):
                    if cve in self.backports:
                        status = VulnerabilityStatus.LIKELY_BACKPORT_PATCHED
                        evidence = "backport patch marker present in release tree"
                    else:
                        status = VulnerabilityStatus.CONFIRMED_VULNERABLE
                        evidence = "advisory version present; no backport marker found"
                    findings.append(
                        Finding(
                            cve=cve,
                            package=pkg,
                            installed_version=version,
                            status=status,
                            severity=severity,
                            evidence=evidence,
                        )
                    )
        return findings


def _scan_dir(ctx: _ScanContext, scan_root: Path, directory: Path, depth: int, prefix: str = "") -> None:
    for dirpath, _, filenames in os.walk(directory):
        for fn in sorted(filenames):
            fp = Path(dirpath) / fn
            rel = prefix + os.path.relpath(fp, scan_root)
            try:
                data = fp.read_bytes()
            except OSError as exc:
                ctx.unchecked.append(
                    UncheckedRegion(
                        kind=UncheckedRegionKind.CORRUPT_ARCHIVE,
                        path=rel,
                        reason=f"unreadable file: {exc}",
                    )
                )
                continue

            ctx.files.append(ExtractedFile(path=rel, sha256=sha256_bytes(data), size=len(data)))

            if _looks_like_archive(rel, data) and depth < MAX_ARCHIVE_DEPTH:
                try:
                    with tempfile.TemporaryDirectory(prefix="fdie-nested-") as td:
                        sub = Path(td) / "inner"
                        extracted = extract_archive(fp, sub)
                        if extracted:
                            _scan_dir(ctx, sub, sub, depth + 1, prefix=f"{rel}#")
                except ArchiveExtractionError as exc:
                    ctx.unchecked.append(
                        UncheckedRegion(
                            kind=UncheckedRegionKind.CORRUPT_ARCHIVE,
                            path=rel,
                            reason=str(exc),
                        )
                    )
                continue

            ctx.secrets.extend(detect_secrets(rel, data))
            blob = classify_blob(rel, data)
            if blob is not None:
                ctx.unchecked.append(blob)
            for version in detect_openssl_versions(data):
                ctx.versions.setdefault("openssl", set()).add(version)
            ctx.backports.update(detect_backport_markers(data))


def scan_archive(archive_path: str | Path) -> ArchiveScanResult:
    """Scan a firmware archive: safe extraction + hash + secrets + coverage gaps.

    Raises ``ArchiveExtractionError`` when the outer archive cannot be read.
    """
    ctx = _ScanContext()
    with tempfile.TemporaryDirectory(prefix="fdie-scan-") as td:
        root = Path(td) / "root"
        extract_archive(archive_path, root)
        _scan_dir(ctx, root, root, depth=0)
    packages = (
        [PackageInfo(name="openssl", version=", ".join(sorted(ctx.versions["openssl"])))]
        if "openssl" in ctx.versions
        else []
    )
    return ArchiveScanResult(
        files=ctx.files,
        secrets=ctx.secrets,
        unchecked=ctx.unchecked,
        packages=packages,
        findings=ctx.build_findings(),
    )


def iter_lines(data: bytes) -> Iterator[tuple[int, str]]:
    """Yield (line_number, decoded_line) for text-ish bytes."""
    text = data.decode("utf-8", "replace")
    for idx, line in enumerate(text.splitlines(), 1):
        yield idx, line
