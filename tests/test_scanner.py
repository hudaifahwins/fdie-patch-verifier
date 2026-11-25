"""Tests for the safe archive scanner: extraction, hashing, secrets, blobs."""
from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from fdie_verifier.models import SecretKind, UncheckedRegionKind, VulnerabilityStatus
from fdie_verifier.scanner import (
    ArchiveExtractionError,
    classify_blob,
    detect_secrets,
    extract_archive,
    scan_archive,
    shannon_entropy,
)

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

def test_extract_tar_gz_lists_files(tmp_path):
    dest = tmp_path / "out"
    paths = extract_archive(FIX / "r1_baseline.tar.gz", dest)
    assert "etc/openssl_version" in paths
    assert "etc/server.key.pem" in paths
    assert "nvram.enc" in paths
    assert (dest / "etc/openssl_version").exists()
    assert (dest / "etc/openssl_version").read_text().startswith("OpenSSL")


def _evil_tar(path: Path, member_name: str, data: bytes = b"EVIL"):
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def test_tar_traversal_rejected(tmp_path):
    evil = tmp_path / "evil.tar"
    _evil_tar(evil, "../escape.txt")
    with pytest.raises(ArchiveExtractionError):
        extract_archive(evil, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_tar_absolute_path_rejected(tmp_path):
    evil = tmp_path / "abs.tar"
    _evil_tar(evil, "/etc/evil")
    with pytest.raises(ArchiveExtractionError):
        extract_archive(evil, tmp_path / "out")
    assert not (tmp_path / "etc" / "evil").exists()


def test_zip_slip_rejected(tmp_path):
    evil = tmp_path / "slip.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../outside.txt", "pwned")
    with pytest.raises(ArchiveExtractionError):
        extract_archive(evil, tmp_path / "out")
    assert not (tmp_path / "outside.txt").exists()


def test_zip_absolute_path_rejected(tmp_path):
    evil = tmp_path / "abs.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("/abs/evil.txt", "pwned")
    with pytest.raises(ArchiveExtractionError):
        extract_archive(evil, tmp_path / "out")
    assert not (tmp_path / "abs" / "evil.txt").exists()


def test_non_archive_rejected(tmp_path):
    not_archive = tmp_path / "file.txt"
    not_archive.write_text("hello")
    with pytest.raises(ArchiveExtractionError):
        extract_archive(not_archive, tmp_path / "out")


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

def test_scan_r1_hashes_match_extracted_content(tmp_path):
    dest = tmp_path / "x"
    extract_archive(FIX / "r1_baseline.tar.gz", dest)
    scan = scan_archive(FIX / "r1_baseline.tar.gz")
    by_path = {f.path: f for f in scan.files}
    assert "etc/openssl_version" in by_path
    for rel, f in by_path.items():
        data = (dest / rel).read_bytes()
        assert f.sha256 == hashlib.sha256(data).hexdigest()
        assert f.size == len(data)


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------

def test_scan_r1_detects_secrets():
    scan = scan_archive(FIX / "r1_baseline.tar.gz")
    kinds = {(s.kind, s.path) for s in scan.secrets}
    assert (SecretKind.PEM_PRIVATE_KEY, "etc/server.key.pem") in kinds
    assert (SecretKind.DEFAULT_CREDENTIAL, "etc/httpd.conf") in kinds
    assert (SecretKind.API_TOKEN, "opt/myapp/token.cfg") in kinds


def test_detect_secrets_line_numbers():
    data = b"user:admin\napi_token=\"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\"\n"
    hits = detect_secrets("test.txt", data)
    by_kind = {h.kind: h for h in hits}
    assert by_kind[SecretKind.DEFAULT_CREDENTIAL].line == 1
    assert by_kind[SecretKind.API_TOKEN].line == 2


def test_scan_r2_has_no_secrets():
    scan = scan_archive(FIX / "r2_fixed.tar.gz")
    assert scan.secrets == []


# ---------------------------------------------------------------------------
# blobs / uncovered regions
# ---------------------------------------------------------------------------

def test_scan_r1_detects_encrypted_region():
    scan = scan_archive(FIX / "r1_baseline.tar.gz")
    encrypted = [u for u in scan.unchecked if u.kind is UncheckedRegionKind.ENCRYPTED]
    assert any(u.path == "nvram.enc" for u in encrypted)


def test_scan_r2_has_no_unchecked_regions():
    scan = scan_archive(FIX / "r2_fixed.tar.gz")
    assert scan.unchecked == []


def test_classify_blob_encryption_magic():
    blob = classify_blob("nvram.enc", b"AES-256-CBC salt:\xff\x00" + b"\x01" * 128)
    assert blob is not None
    assert blob.kind is UncheckedRegionKind.ENCRYPTED


def test_classify_blob_high_entropy():
    data = bytes(range(256)) * 4  # every byte once -> entropy 8.0
    blob = classify_blob("data.bin", data)
    assert blob is not None
    assert blob.kind is UncheckedRegionKind.ENCRYPTED


def test_classify_blob_unsupported_partition():
    blob = classify_blob("rootfs.img", b"hsqs" + b"\x00" * 64)
    assert blob is not None
    assert blob.kind is UncheckedRegionKind.UNSUPPORTED_PARTITION


def test_classify_blob_plain_text_ok():
    assert classify_blob("nvram", b'{"a": 1}') is None


def test_corrupt_nested_archive_detected(tmp_path):
    fake_zip = b"PK\x03\x04" + b"\x00" * 40 + b"this is not a real zip archive"
    tar_path = tmp_path / "outer.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("inner/broken.zip")
        info.size = len(fake_zip)
        tf.addfile(info, io.BytesIO(fake_zip))
    scan = scan_archive(tar_path)
    corrupt = [u for u in scan.unchecked if u.kind is UncheckedRegionKind.CORRUPT_ARCHIVE]
    assert any(u.path == "inner/broken.zip" for u in corrupt)


# ---------------------------------------------------------------------------
# backport classification
# ---------------------------------------------------------------------------

def test_scan_r1_confirmed_vulnerable():
    scan = scan_archive(FIX / "r1_baseline.tar.gz")
    confirmed = {f.cve for f in scan.findings if f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE}
    assert "CVE-2016-6304" in confirmed
    assert "CVE-2016-6303" in confirmed
    assert not any(f.status is VulnerabilityStatus.LIKELY_BACKPORT_PATCHED for f in scan.findings)


def test_scan_r2_backported_patched():
    scan = scan_archive(FIX / "r2_fixed.tar.gz")
    backported = {f.cve for f in scan.findings if f.status is VulnerabilityStatus.LIKELY_BACKPORT_PATCHED}
    assert "CVE-2016-6304" in backported
    assert "CVE-2016-6303" in backported
    assert not any(f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE for f in scan.findings)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0, abs=0.01)
