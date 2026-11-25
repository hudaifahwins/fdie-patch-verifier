"""Tests for the CLI (fdie-verify): exit codes, formats, and file output."""
from __future__ import annotations

import json
from pathlib import Path

from fdie_verifier.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


def test_cli_r1_json_exit_1(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "r1_baseline.tar.gz"),
            "--db", str(tmp_path / "c1.sqlite"),
            "--format", "json",
        ]
    )
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["outcome"]["exit_code"] == 1
    assert data["outcome"]["status"] == "UNVERIFIED_COVERAGE"
    assert data["outcome"]["file_count"] == 6


def test_cli_r2_clean_exit_0(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "r2_fixed.tar.gz"),
            "--db", str(tmp_path / "c0.sqlite"),
            "--format", "text",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out
    assert "BACKPORTED" in out


def test_cli_r2_compare_markdown(tmp_path, capsys):
    db = str(tmp_path / "c2.sqlite")
    assert main(["--input", str(FIX / "r1_baseline.tar.gz"), "--db", db, "--format", "json"]) == 1
    capsys.readouterr()
    code = main(
        [
            "--input", str(FIX / "r2_fixed.tar.gz"),
            "--db", db,
            "--compare-to", "r1_baseline",
            "--format", "markdown",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "## Diff vs baseline `r1_baseline`" in out
    assert "RESOLVED" in out
    assert "CVE-2016-6304" in out


def test_cli_regressed_json_exit_1(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "r2_regressed.json"),
            "--db", str(tmp_path / "c6.sqlite"),
            "--format", "json",
        ]
    )
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["outcome"]["status"] == "UNVERIFIED_COVERAGE"


def test_cli_malformed_exit_2(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "malformed.json"),
            "--db", str(tmp_path / "c3.sqlite"),
            "--format", "json",
        ]
    )
    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert "error" in data
    assert "malformed manifest" in data["error"]


def test_cli_missing_input_exit_2(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "missing.tar.gz"),
            "--db", str(tmp_path / "c4.sqlite"),
            "--format", "text",
        ]
    )
    assert code == 2
    assert "ERROR" in capsys.readouterr().out


def test_cli_output_file(tmp_path):
    db = str(tmp_path / "c5.sqlite")
    outfile = tmp_path / "report.md"
    code = main(
        [
            "--input", str(FIX / "r2_fixed.tar.gz"),
            "--db", db,
            "--format", "markdown",
            "--output", str(outfile),
        ]
    )
    assert code == 0
    text = outfile.read_text()
    assert "CLEAN" in text
    assert "# fdie-patch-verifier" in text


def test_cli_compare_missing_baseline_exit_2(tmp_path, capsys):
    code = main(
        [
            "--input", str(FIX / "r2_fixed.tar.gz"),
            "--db", str(tmp_path / "c7.sqlite"),
            "--compare-to", "nope",
            "--format", "json",
        ]
    )
    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert "baseline release not found" in data["error"]
