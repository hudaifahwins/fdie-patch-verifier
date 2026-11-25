"""SQLite persistence: normalized schema + release-over-release diff queries.

Schema (all rows cascade-deleted when a ``releases`` row is replaced)::

    releases            id, release_id UNIQUE, source, source_type, device,
                        firmware_version, scan_time, status, exit_code,
                        summary, file_hashes (JSON)
    findings            release_id, cve, package, installed_version,
                        fixed_version, status, severity, evidence
    secrets             release_id, kind, path, line, snippet
    unchecked_regions   release_id, kind, path, reason
    meta                schema bookkeeping

Diff categories are computed with real relational SQL (anti-joins) against the
baseline release: ``NEW_EXPOSURE``, ``NEW_SECRET``, ``NEW_BLIND_SPOT`` and
``RESOLVED``.
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Iterator

from .models import (
    DiffReport,
    Finding,
    ReleaseRecord,
    ScanStatus,
    SecretHit,
    UncheckedRegion,
    UncheckedRegionKind,
    VerificationOutcome,
    VulnerabilityStatus,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL,
    device TEXT,
    firmware_version TEXT,
    scan_time TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    summary TEXT NOT NULL,
    file_hashes TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL REFERENCES releases(release_id) ON DELETE CASCADE,
    cve TEXT NOT NULL,
    package TEXT NOT NULL,
    installed_version TEXT,
    fixed_version TEXT,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_release ON findings(release_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve, status);
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL REFERENCES releases(release_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER,
    snippet TEXT
);
CREATE INDEX IF NOT EXISTS idx_secrets_release ON secrets(release_id);
CREATE TABLE IF NOT EXISTS unchecked_regions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL REFERENCES releases(release_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    path TEXT,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_unchecked_release ON unchecked_regions(release_id);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_RELEASE_SELECT = """
SELECT r.id, r.release_id, r.source, r.source_type, r.device, r.firmware_version,
       r.scan_time, r.status, r.exit_code, r.summary,
       (SELECT COUNT(*) FROM findings f WHERE f.release_id = r.release_id) AS finding_count,
       (SELECT COUNT(*) FROM secrets s WHERE s.release_id = r.release_id) AS secret_count,
       (SELECT COUNT(*) FROM unchecked_regions u WHERE u.release_id = r.release_id) AS unchecked_count
FROM releases r
"""

# Anti-join: rows present in the NEW release that are absent from the baseline.
_DIFF_EXPOSURE = """
SELECT f.cve, f.package, f.installed_version, f.fixed_version, f.status,
       f.severity, f.evidence
FROM findings f
JOIN releases r ON r.release_id = f.release_id
WHERE r.release_id = :new AND f.status = 'CONFIRMED_VULNERABLE'
  AND NOT EXISTS (
        SELECT 1 FROM findings fb
        JOIN releases rb ON rb.release_id = fb.release_id
        WHERE rb.release_id = :base
          AND fb.cve = f.cve
          AND fb.status = 'CONFIRMED_VULNERABLE'
      )
ORDER BY f.cve
"""

_DIFF_SECRET = """
SELECT s.kind, s.path, s.line, s.snippet
FROM secrets s
JOIN releases r ON r.release_id = s.release_id
WHERE r.release_id = :new
  AND NOT EXISTS (
        SELECT 1 FROM secrets sb
        JOIN releases rb ON rb.release_id = sb.release_id
        WHERE rb.release_id = :base
          AND sb.kind = s.kind AND sb.path = s.path
      )
ORDER BY s.path
"""

_DIFF_BLIND = """
SELECT u.kind, u.path, u.reason
FROM unchecked_regions u
JOIN releases r ON r.release_id = u.release_id
WHERE r.release_id = :new
  AND NOT EXISTS (
        SELECT 1 FROM unchecked_regions ub
        JOIN releases rb ON rb.release_id = ub.release_id
        WHERE rb.release_id = :base
          AND ub.kind = u.kind AND ub.path = u.path
      )
ORDER BY u.path
"""

# Baseline-confirmed CVEs that are no longer confirmed in the new release
# (removed or replaced by a backport patch marker).
_DIFF_RESOLVED = """
SELECT b.cve, b.package, b.installed_version, b.fixed_version, b.status,
       b.severity, b.evidence
FROM findings b
JOIN releases rb ON rb.release_id = b.release_id
WHERE rb.release_id = :base AND b.status = 'CONFIRMED_VULNERABLE'
  AND NOT EXISTS (
        SELECT 1 FROM findings n
        JOIN releases rn ON rn.release_id = n.release_id
        WHERE rn.release_id = :new
          AND n.cve = b.cve
          AND n.status = 'CONFIRMED_VULNERABLE'
      )
ORDER BY b.cve
"""


class StoreError(Exception):
    """Raised for database-level problems (missing baseline, bad path)."""


class Store:
    """Thin SQLite wrapper for the verifier's history and diff queries."""

    def __init__(self, db_path: str | os.PathLike[str]):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(self.db_path))
            if parent and not os.path.isdir(parent):
                raise StoreError(f"database directory does not exist: {parent}")
        self._init_schema()

    # -- connection helpers -------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')"
            )
            conn.commit()

    # -- release persistence -------------------------------------------------

    def save_release(self, outcome: VerificationOutcome) -> ReleaseRecord:
        """Insert (or replace) a verification outcome, keeping history normalized.

        Re-running the same ``release_id`` replaces the previous scan of that
        release so the history always reflects the latest evidence.
        """
        with self._conn() as conn:
            conn.execute("DELETE FROM findings WHERE release_id = ?", (outcome.release_id,))
            conn.execute("DELETE FROM secrets WHERE release_id = ?", (outcome.release_id,))
            conn.execute(
                "DELETE FROM unchecked_regions WHERE release_id = ?",
                (outcome.release_id,),
            )
            conn.execute("DELETE FROM releases WHERE release_id = ?", (outcome.release_id,))
            conn.execute(
                """
                INSERT INTO releases(release_id, source, source_type, device,
                                     firmware_version, scan_time, status, exit_code,
                                     summary, file_hashes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    outcome.release_id,
                    outcome.source,
                    outcome.source_type,
                    outcome.device,
                    outcome.firmware_version,
                    outcome.scan_time,
                    outcome.status.value,
                    outcome.exit_code,
                    outcome.summary,
                    json.dumps(outcome.file_hashes),
                ),
            )
            for f in outcome.findings:
                conn.execute(
                    """
                    INSERT INTO findings(release_id, cve, package, installed_version,
                                         fixed_version, status, severity, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        outcome.release_id,
                        f.cve,
                        f.package,
                        f.installed_version,
                        f.fixed_version,
                        f.status.value,
                        f.severity.value,
                        f.evidence,
                    ),
                )
            for s in outcome.secrets:
                conn.execute(
                    """
                    INSERT INTO secrets(release_id, kind, path, line, snippet)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (outcome.release_id, s.kind.value, s.path, s.line, s.snippet),
                )
            for u in outcome.unchecked_regions:
                conn.execute(
                    """
                    INSERT INTO unchecked_regions(release_id, kind, path, reason)
                    VALUES (?, ?, ?, ?)
                    """,
                    (outcome.release_id, u.kind.value, u.path, u.reason),
                )
            conn.commit()
        return self.get_release(outcome.release_id)  # type: ignore[return-value]

    # -- queries --------------------------------------------------------------

    def has_release(self, release_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM releases WHERE release_id = ?", (release_id,)
            ).fetchone()
        return row is not None

    def get_release(self, release_id: str) -> ReleaseRecord | None:
        with self._conn() as conn:
            row = conn.execute(
                _RELEASE_SELECT + " WHERE r.release_id = ?", (release_id,)
            ).fetchone()
        return self._row_to_release(row) if row else None

    def list_releases(self) -> list[ReleaseRecord]:
        with self._conn() as conn:
            rows = conn.execute(_RELEASE_SELECT + " ORDER BY r.id DESC").fetchall()
        return [self._row_to_release(row) for row in rows]

    def diff(self, baseline_id: str, new_id: str) -> DiffReport:
        """Compare ``new_id`` against ``baseline_id`` using relational SQL.

        Raises ``StoreError`` if either release is missing from history.
        """
        if not self.has_release(baseline_id):
            raise StoreError(f"baseline release not found in database: {baseline_id}")
        if not self.has_release(new_id):
            raise StoreError(f"release not found in database: {new_id}")
        with self._conn() as conn:
            exposure = conn.execute(
                _DIFF_EXPOSURE, {"base": baseline_id, "new": new_id}
            ).fetchall()
            secrets = conn.execute(
                _DIFF_SECRET, {"base": baseline_id, "new": new_id}
            ).fetchall()
            blind = conn.execute(
                _DIFF_BLIND, {"base": baseline_id, "new": new_id}
            ).fetchall()
            resolved = conn.execute(
                _DIFF_RESOLVED, {"base": baseline_id, "new": new_id}
            ).fetchall()
        return DiffReport(
            baseline_id=baseline_id,
            new_id=new_id,
            new_exposure=[_row_to_finding(row) for row in exposure],
            new_secret=[_row_to_secret(row) for row in secrets],
            new_blind_spot=[_row_to_unchecked(row) for row in blind],
            resolved=[_row_to_finding(row) for row in resolved],
        )

    @staticmethod
    def _row_to_release(row: sqlite3.Row) -> ReleaseRecord:
        return ReleaseRecord(
            id=row["id"],
            release_id=row["release_id"],
            source=row["source"],
            source_type=row["source_type"],
            device=row["device"],
            firmware_version=row["firmware_version"],
            scan_time=row["scan_time"],
            status=ScanStatus(row["status"]),
            exit_code=row["exit_code"],
            summary=row["summary"],
            finding_count=row["finding_count"],
            secret_count=row["secret_count"],
            unchecked_count=row["unchecked_count"],
        )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    from .models import Severity

    return Finding(
        cve=row["cve"],
        package=row["package"],
        installed_version=row["installed_version"],
        fixed_version=row["fixed_version"],
        status=VulnerabilityStatus(row["status"]),
        severity=Severity(row["severity"]),
        evidence=row["evidence"],
    )


def _row_to_secret(row: sqlite3.Row) -> SecretHit:
    from .models import SecretKind

    return SecretHit(
        kind=SecretKind(row["kind"]),
        path=row["path"],
        line=row["line"],
        snippet=row["snippet"],
    )


def _row_to_unchecked(row: sqlite3.Row) -> UncheckedRegion:
    return UncheckedRegion(
        kind=UncheckedRegionKind(row["kind"]),
        path=row["path"],
        reason=row["reason"],
    )
