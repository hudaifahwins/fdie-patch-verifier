# fdie-patch-verifier

Firmware security & release-diff verification in one tool. It answers three
questions release engineers actually care about:

1. **Can I trust this firmware image?** Safe `.tar.gz`/`.zip` extraction with
   zip-slip/path-traversal protection, SHA-256 hashing of every extracted file,
   package/version metadata inspection, and hardcoded-secret detection (PEM
   private keys, default `admin:admin` credentials, hardcoded API tokens).
2. **Is this CVE really exploitable, or just not version-bumped?** The scanner
   distinguishes `LIKELY_BACKPORT_PATCHED` packages (backport patch markers
   present in the tree) from `CONFIRMED_VULNERABLE` ones, so teams don't drown
   in false-positive noise when upstream versions aren't bumped.
3. **Did we actually cover the whole image?** Any encrypted blob, corrupt inner
   archive, or unsupported partition is recorded as an unchecked region and
   forces an explicit `UNVERIFIED_COVERAGE` status + non-zero exit code — a
   partial scan can never silently pass as clean.

Every scan run, finding, secret hit, and unchecked region is persisted into a
normalized SQLite database (`sqlite3`), which powers release-over-release diffs
(`NEW_EXPOSURE`, `NEW_SECRET`, `NEW_BLIND_SPOT`, `RESOLVED`) via real SQL, a
FastAPI REST API, and an interactive localhost web dashboard.

---

## Install

```bash
cd fdie-patch-verifier
python3 -m venv .venv
.venv/bin/pip install -e .
```

Requires Python 3.11+. Dependencies: `fastapi`, `pydantic`, `uvicorn`,
`pytest`, `httpx`.

## Generate fixture firmware bundles

```bash
python3 fixtures/generate_fixtures.py
```

This creates strictly synthetic fixtures (no real/proprietary data):

| Fixture | Type | What it demonstrates | Exit code |
|---|---|---|---|
| `fixtures/r1_baseline.tar.gz` | archive | unpatched OpenSSL CVEs, dummy private key, `admin:admin`, API token, encrypted `nvram.enc` | `1` |
| `fixtures/r2_fixed.tar.gz` | archive | backported OpenSSL fix, secrets removed, `nvram` plain | `0` |
| `fixtures/r2_regressed.json` | manifest | new exposure + new blind spot | `1` |
| `fixtures/malformed.json` | manifest | corrupt/missing fields | `2` |

## Run tests

```bash
.venv/bin/pytest -v
```

## CLI

```bash
# verify the baseline (exit 1: vulnerabilities + secrets + unchecked region)
.venv/bin/fdie-verify --input fixtures/r1_baseline.tar.gz --db demo.sqlite

# verify the fixed release against the baseline (exit 0, RESOLVED diff)
.venv/bin/fdie-verify --input fixtures/r2_fixed.tar.gz --db demo.sqlite \
  --compare-to r1_baseline --format markdown

# manifest with a new exposure + blind spot (exit 1)
.venv/bin/fdie-verify --input fixtures/r2_regressed.json --db demo.sqlite \
  --compare-to r1_baseline --format json

# malformed manifest (exit 2)
.venv/bin/fdie-verify --input fixtures/malformed.json --db demo.sqlite
```

Options: `--input FILE` (required), `--db PATH` (default `verifier.sqlite`),
`--compare-to BASELINE_ID`, `--format text|json|markdown`, `--output FILE`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean / verified |
| `1` | confirmed vulnerabilities, secrets, or unverified blind spots (any of them) |
| `2` | invalid / malformed input |

## Dashboard + REST API (localhost)

```bash
FDIE_VERIFIER_DB=demo.sqlite nohup .venv/bin/uvicorn fdie_verifier.api:app \
  --host 127.0.0.1 --port 8001 > server.log 2>&1 &
```

Open http://localhost:8001 — the dashboard shows the release history, lets you
run live scans on the sample fixtures, and explore release-over-release diffs
in the browser. REST endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | service + database health |
| `POST` | `/verify` | run a scan (`{"input": "...", "compare_to": "..."}`) |
| `GET` | `/releases` | persisted release history |
| `GET` | `/releases/{release_id}/diff/{baseline_id}` | release diff |

## Design Choices

### SQLite relational diff queries
The DB schema is normalized: `releases`, `findings`, `secrets`,
`unchecked_regions`, `meta`. Diffs are executed as real relational SQL using
anti-joins (e.g. `NOT EXISTS`) against the baseline release rather than doing
set arithmetic in Python. Example — `NEW_EXPOSURE`:

```sql
SELECT f.cve, f.package, f.installed_version, f.fixed_version, f.severity, f.evidence
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
```

`NEW_SECRET` and `NEW_BLIND_SPOT` use the same anti-join pattern on the
`secrets` / `unchecked_regions` tables; `RESOLVED` is the mirror image
(baseline-confirmed CVEs no longer confirmed in the new release — either
removed or replaced by a backport marker). Keeping the comparison in the
database means the semantics live with the data, work with any client (CLI,
REST, dashboard), and stay consistent as history grows.

### Explicit `UNVERIFIED_COVERAGE` gating
A scan that finds zero vulnerabilities and zero secrets can still be lying — if
part of the firmware was encrypted, corrupt, or in an unsupported partition, we
simply could not inspect it. The classifier therefore checks unchecked regions
**first**: any unchecked region flips the status to `UNVERIFIED_COVERAGE` and
forces exit code `1`, regardless of what else was found. A partial scan can
never pass as clean; it is loudly marked as incomplete.

### Safe extraction
`extract_archive` rejects zip-slip/path-traversal members (relative `..`
escapes, absolute paths), never materializes symlink/hardlink members, and
enforces file-count and uncompressed-size limits (zip-bomb guard). Nested
archives are scanned recursively (depth-limited); corrupt nested archives are
recorded as unchecked regions.

### Backport-aware classification
OpenSSL versions found in the tree are matched against a small advisory table.
If a backport patch marker (`BACKPORT: CVE-…`) exists anywhere in the release
for that CVE, the finding is classified `LIKELY_BACKPORT_PATCHED` — informing
engineers that the upstream version wasn't bumped but the fix was shipped — and
does not fail the build.

## Sample output

```
$ .venv/bin/fdie-verify --input fixtures/r1_baseline.tar.gz --db demo.sqlite
fdie-patch-verifier report
  release      : r1_baseline
  source       : fixtures/r1_baseline.tar.gz (archive)
  status       : UNVERIFIED_COVERAGE
  exit code    : 1
  scanned files: 6 (2870 bytes)
  scan time    : 2026-11-25T15:24:56Z

Findings:
  [VULN] CVE-2016-6304 openssl 1.0.2u (HIGH)
        advisory version present; no backport marker found
  [VULN] CVE-2016-6303 openssl 1.0.2u (MEDIUM)
        advisory version present; no backport marker found

Secrets:
  [default_credential] etc/httpd.conf:2 admin:admin
  [pem_private_key] etc/server.key.pem:1 -----BEGIN RSA PRIVATE KEY-----
  [api_token] opt/myapp/token.cfg:1 api_token="kQx9vT2mN4pR7sW1uY8zA3cE6fH0jL5oB"

Unchecked regions:
  [encrypted] nvram.enc: encryption magic 'AES-256-CBC'
```

```
$ .venv/bin/fdie-verify --input fixtures/r2_fixed.tar.gz --db demo.sqlite \
    --compare-to r1_baseline --format markdown | tail -12
## Diff vs baseline `r1_baseline`

- **NEW_EXPOSURE:** 0
- **NEW_SECRET:** 0
- **NEW_BLIND_SPOT:** 0
- **RESOLVED:** 2

### Resolved
- `CVE-2016-6304` in `openssl`
- `CVE-2016-6303` in `openssl`
```
