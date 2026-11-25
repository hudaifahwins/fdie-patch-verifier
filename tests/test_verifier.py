"""Tests for the verification engine: outcomes, exit codes, and diffs."""
from __future__ import annotations

from pathlib import Path

import pytest

from fdie_verifier.models import ScanStatus, UncheckedRegionKind, VulnerabilityStatus
from fdie_verifier.verifier import (
    InvalidInputError,
    classify_outcome,
    perform_verification,
    verify_input,
)

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


# ---------------------------------------------------------------------------
# standalone verification outcomes
# ---------------------------------------------------------------------------

def test_r1_baseline_exits_1():
    outcome = verify_input(FIX / "r1_baseline.tar.gz")
    assert outcome.exit_code == 1
    assert outcome.status is ScanStatus.UNVERIFIED_COVERAGE
    assert any(
        u.kind is UncheckedRegionKind.ENCRYPTED and u.path == "nvram.enc"
        for u in outcome.unchecked_regions
    )
    assert any(
        f.cve == "CVE-2016-6304"
        and f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE
        for f in outcome.findings
    )
    assert len(outcome.secrets) == 3


def test_r2_fixed_clean_exits_0():
    outcome = verify_input(FIX / "r2_fixed.tar.gz")
    assert outcome.exit_code == 0
    assert outcome.status is ScanStatus.CLEAN
    assert outcome.secrets == []
    assert outcome.unchecked_regions == []
    backported = {
        f.cve for f in outcome.findings if f.status is VulnerabilityStatus.LIKELY_BACKPORT_PATCHED
    }
    assert "CVE-2016-6304" in backported
    assert not any(
        f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE for f in outcome.findings
    )


def test_r2_regressed_exits_1():
    outcome = verify_input(FIX / "r2_regressed.json")
    assert outcome.exit_code == 1
    assert outcome.status is ScanStatus.UNVERIFIED_COVERAGE
    assert "CVE-2018-0739" in {f.cve for f in outcome.findings}
    assert any(u.path == "syscfg.bin" for u in outcome.unchecked_regions)


def test_malformed_manifest_raises():
    with pytest.raises(InvalidInputError) as excinfo:
        verify_input(FIX / "malformed.json")
    assert "malformed manifest" in str(excinfo.value)


def test_missing_input_raises():
    with pytest.raises(InvalidInputError):
        verify_input(FIX / "does-not-exist.tar.gz")


def test_unsafe_archive_raises(tmp_path):
    evil = tmp_path / "evil.tar"
    import tarfile as tf_mod
    import io as io_mod

    with tf_mod.open(evil, "w") as tf:
        info = tf_mod.TarInfo("../escape")
        info.size = 4
        tf.addfile(info, io_mod.BytesIO(b"EVIL"))
    with pytest.raises(InvalidInputError):
        verify_input(evil)


def test_classify_outcome_priority():
    from fdie_verifier.models import Finding, ScanResult, SecretHit

    vuln = Finding(cve="CVE-2014-0160", status=VulnerabilityStatus.CONFIRMED_VULNERABLE)
    secret = SecretHit(kind=__import__("fdie_verifier.models", fromlist=["SecretKind"]).SecretKind.API_TOKEN, path="a", snippet="x")
    base = dict(release_id="r", source="s", source_type="archive")

    status, code = classify_outcome(ScanResult(**base))
    assert (status, code) == (ScanStatus.CLEAN, 0)

    status, code = classify_outcome(ScanResult(**base, findings=[vuln]))
    assert (status, code) == (ScanStatus.VULNERABLE, 1)

    status, code = classify_outcome(ScanResult(**base, secrets=[secret]))
    assert (status, code) == (ScanStatus.VULNERABLE, 1)

    from fdie_verifier.models import UncheckedRegion
    status, code = classify_outcome(
        ScanResult(**base, secrets=[secret], unchecked_regions=[UncheckedRegion(kind=UncheckedRegionKind.ENCRYPTED, path="p", reason="r")])
    )
    assert (status, code) == (ScanStatus.UNVERIFIED_COVERAGE, 1)


# ---------------------------------------------------------------------------
# release-over-release diff
# ---------------------------------------------------------------------------

def test_diff_r2_fixed_vs_r1_resolves(tmp_path):
    db = tmp_path / "d.sqlite"
    perform_verification(FIX / "r1_baseline.tar.gz", db)
    outcome, diff = perform_verification(FIX / "r2_fixed.tar.gz", db, compare_to="r1_baseline")
    assert outcome.exit_code == 0
    assert diff is not None
    assert diff.baseline_id == "r1_baseline"
    assert diff.new_id == "r2_fixed"
    assert {f.cve for f in diff.resolved} >= {"CVE-2016-6304", "CVE-2016-6303"}
    assert diff.new_exposure == []
    assert diff.new_secret == []
    assert diff.new_blind_spot == []


def test_diff_regressed_vs_baseline(tmp_path):
    db = tmp_path / "d2.sqlite"
    perform_verification(FIX / "r1_baseline.tar.gz", db)
    outcome, diff = perform_verification(FIX / "r2_regressed.json", db, compare_to="r1_baseline")
    assert outcome.exit_code == 1
    assert diff is not None
    assert {f.cve for f in diff.new_exposure} == {"CVE-2018-0739"}
    assert any(u.path == "syscfg.bin" for u in diff.new_blind_spot)
    assert {f.cve for f in diff.resolved} >= {"CVE-2016-6304"}
    assert diff.new_secret == []


def test_compare_missing_baseline_raises(tmp_path):
    db = tmp_path / "d3.sqlite"
    with pytest.raises(InvalidInputError):
        perform_verification(FIX / "r2_fixed.tar.gz", db, compare_to="does-not-exist")


def test_persistence_after_cli_style_runs(tmp_path):
    db = tmp_path / "d4.sqlite"
    perform_verification(FIX / "r1_baseline.tar.gz", db)
    perform_verification(FIX / "r2_fixed.tar.gz", db)
    from fdie_verifier.store import Store

    store = Store(db)
    releases = {r.release_id: r for r in store.list_releases()}
    assert releases["r1_baseline"].exit_code == 1
    assert releases["r2_fixed"].exit_code == 0
    assert releases["r1_baseline"].secret_count == 3
    assert releases["r1_baseline"].unchecked_count == 1
