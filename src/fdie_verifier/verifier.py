"""Verification engine: orchestrate scanning, classification and diffing.

Exit-code contract (enforced by :func:`classify_outcome`):

* ``0`` — clean/verified: no confirmed vulnerabilities, no secrets, and full
  coverage (zero unchecked regions).
* ``1`` — at least one confirmed vulnerability, secret hit, OR unchecked
  region. Unchecked regions take priority and force the explicit
  ``UNVERIFIED_COVERAGE`` status so partial scans can never pass as clean.
* ``2`` — invalid/malformed input (missing file, malformed manifest, unsafe or
  unreadable archive, missing baseline).
"""
from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from . import scanner
from .models import (
    FirmwareManifest,
    ScanResult,
    ScanStatus,
    VerificationOutcome,
    VulnerabilityStatus,
)
from .scanner import ArchiveExtractionError
from .store import Store, StoreError


class InvalidInputError(Exception):
    """Input could not be interpreted (missing file, malformed manifest, unsafe archive)."""


def _derive_release_id(source: Path) -> str:
    """Derive a stable release_id from an archive filename (r1_baseline.tar.gz
    -> ``r1_baseline``)."""
    name = source.name
    while True:
        for suffix in (".tar.gz", ".tgz", ".tar", ".zip", ".json", ".gz"):
            if name.lower().endswith(suffix):
                name = name[: -len(suffix)]
                break
        else:
            return name or "release"


def load_manifest(path: Path) -> FirmwareManifest:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"cannot read manifest {path}: {exc}") from exc
    try:
        return FirmwareManifest.model_validate_json(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise InvalidInputError(f"malformed manifest: {details}") from exc


def classify_outcome(result: ScanResult) -> tuple[ScanStatus, int]:
    """Exit-code policy: unverified coverage gates first, then vulns/secrets."""
    if result.unchecked_regions:
        return ScanStatus.UNVERIFIED_COVERAGE, 1
    if (
        any(f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE for f in result.findings)
        or result.secrets
    ):
        return ScanStatus.VULNERABLE, 1
    return ScanStatus.CLEAN, 0


def verify_input(input_path: str | Path) -> VerificationOutcome:
    """Verify one firmware input (JSON manifest or archive) and return the outcome.

    Raises ``InvalidInputError`` for malformed/missing/unsafe input.
    """
    path = Path(input_path)
    if not path.exists():
        raise InvalidInputError(f"input file not found: {path}")

    if path.suffix.lower() == ".json":
        manifest = load_manifest(path)
        result = ScanResult.from_manifest(manifest, source=str(path))
        status, code = classify_outcome(result)
        return VerificationOutcome.from_scan(result, status, code)

    try:
        scan = scanner.scan_archive(path)
    except ArchiveExtractionError as exc:
        raise InvalidInputError(str(exc)) from exc

    result = ScanResult(
        release_id=_derive_release_id(path),
        source=str(path),
        source_type="archive",
        files=scan.files,
        packages=scan.packages,
        findings=scan.findings,
        secrets=scan.secrets,
        unchecked_regions=scan.unchecked,
    )
    status, code = classify_outcome(result)
    return VerificationOutcome.from_scan(result, status, code)


def perform_verification(
    input_path: str | Path,
    db_path: str,
    compare_to: str | None = None,
) -> tuple[VerificationOutcome, object]:
    """Verify input, persist to ``db_path``, and optionally diff against a baseline.

    Returns ``(outcome, diff_report_or_None)``. Raises ``InvalidInputError`` for
    malformed input or a missing baseline release.
    """
    outcome = verify_input(input_path)
    store = Store(db_path)
    if compare_to is not None and not store.has_release(compare_to):
        raise InvalidInputError(
            f"baseline release not found in database '{db_path}': {compare_to}"
        )
    store.save_release(outcome)
    diff = None
    if compare_to is not None:
        try:
            diff = store.diff(compare_to, outcome.release_id)
        except StoreError as exc:
            raise InvalidInputError(str(exc)) from exc
    return outcome, diff
