"""Tests for the SQLite store: schema, persistence, and diff queries."""
from __future__ import annotations

from pathlib import Path

import pytest

from fdie_verifier.store import Store, StoreError
from fdie_verifier.verifier import verify_input

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


def test_schema_tables_exist(tmp_path):
    store = Store(tmp_path / "s.sqlite")
    with store._conn() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    names = {row["name"] for row in rows}
    assert {"releases", "findings", "secrets", "unchecked_regions", "meta"} <= names


def test_save_release_and_read_back(tmp_path):
    store = Store(tmp_path / "s2.sqlite")
    outcome = verify_input(FIX / "r1_baseline.tar.gz")
    store.save_release(outcome)
    assert store.has_release("r1_baseline")
    rec = store.get_release("r1_baseline")
    assert rec is not None
    assert rec.exit_code == 1
    assert rec.status.value == "UNVERIFIED_COVERAGE"
    assert rec.finding_count == len(outcome.findings)
    assert rec.secret_count == len(outcome.secrets)
    assert rec.unchecked_count == len(outcome.unchecked_regions)


def test_save_replaces_same_release_id(tmp_path):
    store = Store(tmp_path / "s3.sqlite")
    outcome = verify_input(FIX / "r1_baseline.tar.gz")
    store.save_release(outcome)
    store.save_release(outcome)
    releases = store.list_releases()
    assert len(releases) == 1
    assert releases[0].finding_count == len(outcome.findings)


def test_persistence_across_reopen(tmp_path):
    db = tmp_path / "s4.sqlite"
    Store(db).save_release(verify_input(FIX / "r1_baseline.tar.gz"))
    reopened = Store(db)
    assert reopened.has_release("r1_baseline")
    rec = reopened.list_releases()[0]
    assert rec.secret_count == 3
    assert rec.unchecked_count == 1


def test_diff_queries_against_baseline(tmp_path):
    db = tmp_path / "s5.sqlite"
    store = Store(db)
    store.save_release(verify_input(FIX / "r1_baseline.tar.gz"))
    store.save_release(verify_input(FIX / "r2_fixed.tar.gz"))

    diff = store.diff("r1_baseline", "r2_fixed")
    assert diff.new_exposure == []
    assert diff.new_secret == []
    assert diff.new_blind_spot == []
    assert {f.cve for f in diff.resolved} >= {"CVE-2016-6304", "CVE-2016-6303"}

    regressed = verify_input(FIX / "r2_regressed.json")
    store.save_release(regressed)
    diff2 = store.diff("r1_baseline", "r2_regressed")
    assert {f.cve for f in diff2.new_exposure} == {"CVE-2018-0739"}
    assert any(u.path == "syscfg.bin" for u in diff2.new_blind_spot)
    assert {f.cve for f in diff2.resolved} >= {"CVE-2016-6304"}


def test_diff_missing_release_raises(tmp_path):
    store = Store(tmp_path / "s6.sqlite")
    store.save_release(verify_input(FIX / "r1_baseline.tar.gz"))
    with pytest.raises(StoreError):
        store.diff("nope", "r1_baseline")
    with pytest.raises(StoreError):
        store.diff("r1_baseline", "nope")


def test_missing_db_directory_raises(tmp_path):
    with pytest.raises(StoreError):
        Store(tmp_path / "no_such_dir" / "db.sqlite")
