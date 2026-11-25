"""Tests for the FastAPI service: health, dashboard, verify, releases, diff."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fdie_verifier.api import create_app

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


@pytest.fixture()
def client(tmp_path) -> TestClient:
    app = create_app(db_path=str(tmp_path / "api.sqlite"))
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "fdie-patch-verifier"


def test_index_serves_html_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    html = r.text.lower()
    assert "<html" in html
    assert "release" in html
    assert "diff" in html


def test_verify_archive_endpoint(client):
    r = client.post("/verify", json={"input": str(FIX / "r1_baseline.tar.gz")})
    assert r.status_code == 200
    body = r.json()
    oc = body["outcome"]
    assert oc["release_id"] == "r1_baseline"
    assert oc["exit_code"] == 1
    assert oc["status"] == "UNVERIFIED_COVERAGE"
    assert len(oc["secrets"]) == 3
    assert oc["file_count"] == 6
    assert oc["file_hashes"]["etc/openssl_version"]


def test_verify_with_compare_to(client):
    assert client.post("/verify", json={"input": str(FIX / "r1_baseline.tar.gz")}).status_code == 200
    r = client.post(
        "/verify",
        json={"input": str(FIX / "r2_fixed.tar.gz"), "compare_to": "r1_baseline"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["diff"] is not None
    d = body["diff"]
    assert d["baseline_id"] == "r1_baseline"
    assert any(f["cve"] == "CVE-2016-6304" for f in d["resolved"])
    assert d["new_exposure"] == []


def test_verify_missing_input_404(client):
    r = client.post("/verify", json={"input": "/nonexistent/file.tar.gz"})
    assert r.status_code == 404


def test_verify_malformed_manifest_400(client):
    r = client.post("/verify", json={"input": str(FIX / "malformed.json")})
    assert r.status_code == 400
    assert "malformed manifest" in r.json()["detail"]


def test_releases_listing(client):
    client.post("/verify", json={"input": str(FIX / "r1_baseline.tar.gz")})
    r = client.get("/releases")
    assert r.status_code == 200
    rels = r.json()
    assert any(
        x["release_id"] == "r1_baseline" and x["exit_code"] == 1 and x["secret_count"] == 3
        for x in rels
    )


def test_diff_endpoint(client):
    client.post("/verify", json={"input": str(FIX / "r1_baseline.tar.gz")})
    client.post("/verify", json={"input": str(FIX / "r2_fixed.tar.gz")})
    r = client.get("/releases/r2_fixed/diff/r1_baseline")
    assert r.status_code == 200
    body = r.json()
    assert body["baseline_id"] == "r1_baseline"
    assert body["new_id"] == "r2_fixed"
    assert any(f["cve"] == "CVE-2016-6304" for f in body["resolved"])
    assert body["new_blind_spot"] == []

    assert client.get("/releases/nope/diff/r1_baseline").status_code == 404
    assert client.get("/releases/r2_fixed/diff/nope").status_code == 404
