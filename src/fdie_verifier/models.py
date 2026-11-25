"""Strict typed models and validation for fdie-patch-verifier.

All input models use pydantic v2 validators so malformed manifests and payloads
fail fast with clear, actionable error messages (never silent truncation).
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

VALID_CVE_RE = r"^CVE-\d{4}-\d{4,}$"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VulnerabilityStatus(str, enum.Enum):
    """Classification of a CVE finding in a release."""

    LIKELY_BACKPORT_PATCHED = "LIKELY_BACKPORT_PATCHED"
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"


class ScanStatus(str, enum.Enum):
    """Overall verification outcome for a release."""

    CLEAN = "CLEAN"
    VULNERABLE = "VULNERABLE"
    UNVERIFIED_COVERAGE = "UNVERIFIED_COVERAGE"
    INVALID = "INVALID"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UncheckedRegionKind(str, enum.Enum):
    """Kinds of regions the scanner cannot inspect."""

    ENCRYPTED = "encrypted"
    CORRUPT_ARCHIVE = "corrupt_archive"
    UNSUPPORTED_PARTITION = "unsupported_partition"


class SecretKind(str, enum.Enum):
    PEM_PRIVATE_KEY = "pem_private_key"
    DEFAULT_CREDENTIAL = "default_credential"
    API_TOKEN = "api_token"
    AWS_ACCESS_KEY = "aws_access_key"
    GENERIC_SECRET = "generic_secret"


class PackageInfo(BaseModel):
    name: str = Field(min_length=1)
    version: str | None = None
    license: str | None = None
    symbols: list[str] = Field(default_factory=list)


class VulnerabilityDecl(BaseModel):
    """A vulnerability declared inside a JSON firmware manifest."""

    cve: str = Field(pattern=VALID_CVE_RE)
    package: str = "unknown"
    installed_version: str | None = None
    fixed_version: str | None = None
    backported: bool = False
    severity: Severity = Severity.HIGH
    evidence: str | None = None

    @property
    def status(self) -> VulnerabilityStatus:
        return (
            VulnerabilityStatus.LIKELY_BACKPORT_PATCHED
            if self.backported
            else VulnerabilityStatus.CONFIRMED_VULNERABLE
        )


class SecretDecl(BaseModel):
    kind: SecretKind
    path: str = ""
    line: int | None = None
    snippet: str = ""


class UncheckedRegionDecl(BaseModel):
    kind: UncheckedRegionKind
    path: str | None = None
    reason: str = Field(min_length=1)


class FirmwareManifest(BaseModel):
    """Top-level JSON manifest accepted as an alternative to an archive."""

    release_id: str = Field(min_length=1)
    device: str | None = None
    firmware_version: str | None = None
    packages: list[PackageInfo] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityDecl] = Field(default_factory=list)
    secrets: list[SecretDecl] = Field(default_factory=list)
    unchecked_regions: list[UncheckedRegionDecl] = Field(default_factory=list)


class Finding(BaseModel):
    cve: str
    package: str = "unknown"
    installed_version: str | None = None
    fixed_version: str | None = None
    status: VulnerabilityStatus
    severity: Severity = Severity.HIGH
    evidence: str | None = None


class SecretHit(BaseModel):
    kind: SecretKind
    path: str
    line: int | None = None
    snippet: str = ""


class UncheckedRegion(BaseModel):
    kind: UncheckedRegionKind
    path: str | None = None
    reason: str


class ExtractedFile(BaseModel):
    path: str
    sha256: str
    size: int


class ScanResult(BaseModel):
    """Normalized result of inspecting one firmware input (archive or manifest)."""

    release_id: str
    source: str
    source_type: Literal["archive", "manifest"]
    device: str | None = None
    firmware_version: str | None = None
    files: list[ExtractedFile] = Field(default_factory=list)
    packages: list[PackageInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    secrets: list[SecretHit] = Field(default_factory=list)
    unchecked_regions: list[UncheckedRegion] = Field(default_factory=list)
    scan_time: str = Field(default_factory=_now_iso)

    @classmethod
    def from_manifest(cls, manifest: FirmwareManifest, source: str) -> "ScanResult":
        findings = [
            Finding(
                cve=v.cve,
                package=v.package,
                installed_version=v.installed_version,
                fixed_version=v.fixed_version,
                status=v.status,
                severity=v.severity,
                evidence=v.evidence,
            )
            for v in manifest.vulnerabilities
        ]
        return cls(
            release_id=manifest.release_id,
            source=source,
            source_type="manifest",
            device=manifest.device,
            firmware_version=manifest.firmware_version,
            packages=manifest.packages,
            findings=findings,
            secrets=[
                SecretHit(kind=s.kind, path=s.path, line=s.line, snippet=s.snippet)
                for s in manifest.secrets
            ],
            unchecked_regions=[
                UncheckedRegion(kind=u.kind, path=u.path, reason=u.reason)
                for u in manifest.unchecked_regions
            ],
        )


class ReleaseRecord(BaseModel):
    """One row of the releases history table (with aggregate counts)."""

    id: int
    release_id: str
    source: str
    source_type: str
    device: str | None = None
    firmware_version: str | None = None
    scan_time: str
    status: ScanStatus
    exit_code: int
    summary: str
    finding_count: int = 0
    secret_count: int = 0
    unchecked_count: int = 0


class DiffReport(BaseModel):
    """Release-over-release comparison against a stored baseline."""

    baseline_id: str
    new_id: str
    new_exposure: list[Finding] = Field(default_factory=list)
    new_secret: list[SecretHit] = Field(default_factory=list)
    new_blind_spot: list[UncheckedRegion] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)


class VerificationOutcome(BaseModel):
    """Full, persisted verification result for one release."""

    release_id: str
    source: str
    source_type: Literal["archive", "manifest"]
    device: str | None = None
    firmware_version: str | None = None
    status: ScanStatus
    exit_code: int
    findings: list[Finding] = Field(default_factory=list)
    secrets: list[SecretHit] = Field(default_factory=list)
    unchecked_regions: list[UncheckedRegion] = Field(default_factory=list)
    packages: list[PackageInfo] = Field(default_factory=list)
    file_count: int = 0
    bytes_total: int = 0
    file_hashes: dict[str, str] = Field(default_factory=dict)
    scan_time: str = Field(default_factory=_now_iso)
    summary: str = ""

    @classmethod
    def from_scan(
        cls, result: ScanResult, status: ScanStatus, exit_code: int
    ) -> "VerificationOutcome":
        return cls(
            release_id=result.release_id,
            source=result.source,
            source_type=result.source_type,
            device=result.device,
            firmware_version=result.firmware_version,
            status=status,
            exit_code=exit_code,
            findings=result.findings,
            secrets=result.secrets,
            unchecked_regions=result.unchecked_regions,
            packages=result.packages,
            file_count=len(result.files),
            bytes_total=sum(f.size for f in result.files),
            file_hashes={f.path: f.sha256 for f in result.files},
            scan_time=result.scan_time,
            summary=_summarize(status, result.findings, result.secrets, result.unchecked_regions),
        )


def _summarize(
    status: ScanStatus,
    findings: list[Finding],
    secrets: list[SecretHit],
    unchecked: list[UncheckedRegion],
) -> str:
    parts: list[str] = []
    if status is ScanStatus.UNVERIFIED_COVERAGE:
        parts.append(f"unverified coverage: {len(unchecked)} unchecked region(s)")
    confirmed = [f for f in findings if f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE]
    if confirmed:
        n = len(confirmed)
        parts.append(f"{n} confirmed vulnerabilit{'y' if n == 1 else 'ies'}")
    if secrets:
        parts.append(f"{len(secrets)} secret hit(s)")
    backported = [f for f in findings if f.status is VulnerabilityStatus.LIKELY_BACKPORT_PATCHED]
    if backported:
        parts.append(f"{len(backported)} likely backported fix(es)")
    return "; ".join(parts) if parts else "clean"
