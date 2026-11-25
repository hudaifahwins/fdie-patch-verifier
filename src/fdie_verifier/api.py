"""FastAPI service for fdie-patch-verifier.

Serves:

* ``GET /`` — single-page interactive HTML/JS dashboard (release history, live
  scans against local fixtures, and release-over-release diffs).
* ``GET /health`` — service/database health.
* ``POST /verify`` — run a live verification on an input path (JSON body:
  ``{"input": "...", "compare_to": "..."}``).
* ``GET /releases`` — persisted release history.
* ``GET /releases/{release_id}/diff/{baseline_id}`` — diff of one release vs a
  baseline.

The database path is resolved from the ``FDIE_VERIFIER_DB`` environment
variable (default ``demo.sqlite``) so the server shares history with the CLI.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .store import Store, StoreError
from .verifier import InvalidInputError, perform_verification

DEFAULT_DB = "demo.sqlite"


def _env_db() -> str:
    return os.environ.get("FDIE_VERIFIER_DB", DEFAULT_DB)


class VerifyRequest(BaseModel):
    input: str = Field(min_length=1)
    compare_to: str | None = None


def create_app(db_path: str | None = None) -> FastAPI:
    db = db_path or _env_db()
    app = FastAPI(
        title="fdie-patch-verifier",
        version="0.1.0",
        description="Firmware security & release-diff verifier",
    )
    app.state.db_path = db

    def store() -> Store:
        return Store(db)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "fdie-patch-verifier",
            "database": db,
            "time": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/verify")
    def verify(req: VerifyRequest) -> dict[str, object]:
        try:
            outcome, diff = perform_verification(req.input, db, req.compare_to)
        except InvalidInputError as exc:
            if not Path(req.input).exists():
                raise HTTPException(status_code=404, detail=f"input not found: {req.input}")
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "outcome": outcome.model_dump(),
            "diff": diff.model_dump() if diff is not None else None,
        }

    @app.get("/releases")
    def releases() -> list[dict[str, object]]:
        return [r.model_dump() for r in store().list_releases()]

    @app.get("/releases/{release_id}/diff/{baseline_id}")
    def release_diff(release_id: str, baseline_id: str) -> dict[str, object]:
        try:
            report = store().diff(baseline_id, release_id)
        except StoreError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return report.model_dump()

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    return app


app = create_app()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fdie · patch verifier</title>
<style>
  :root {
    --bg:#0b1020; --panel:#131a2e; --panel2:#0f1526; --line:#24304d;
    --text:#e6ebf5; --muted:#8b98b8; --accent:#5eead4; --good:#34d399;
    --warn:#fbbf24; --bad:#f87171; --neut:#94a3b8; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  header { display:flex; align-items:center; justify-content:space-between; padding:16px 28px; border-bottom:1px solid var(--line); background:var(--panel2); }
  .brand { font-weight:700; font-size:18px; letter-spacing:.3px; }
  .brand span { color:var(--accent); padding:0 4px; }
  .pill { font-family:var(--mono); font-size:12px; color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:4px 12px; }
  main { max-width:1180px; margin:0 auto; padding:24px 28px 60px; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px 20px; }
  .card.span2 { grid-column:span 2; }
  h2,h3,h4 { margin:.2em 0 .6em; font-weight:600; }
  h2 { font-size:16px; letter-spacing:.4px; text-transform:uppercase; color:var(--muted); }
  .muted { color:var(--muted); font-size:13px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th { text-align:left; color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.4px; padding:6px 8px; border-bottom:1px solid var(--line); }
  td { padding:7px 8px; border-bottom:1px solid var(--line); }
  .mono { font-family:var(--mono); }
  .small { font-size:12.5px; color:var(--muted); }
  .center { text-align:center; }
  .badge { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:700; letter-spacing:.4px; }
  .good { background:rgba(52,211,153,.14); color:var(--good); }
  .warn { background:rgba(251,191,36,.14); color:var(--warn); }
  .bad { background:rgba(248,113,113,.14); color:var(--bad); }
  .neut { background:rgba(148,163,184,.14); color:var(--neut); }
  label { display:block; font-size:12.5px; color:var(--muted); margin:12px 0 5px; }
  select, button { width:100%; border:1px solid var(--line); background:var(--panel2); color:var(--text); border-radius:9px; padding:9px 11px; font-size:14px; }
  select { font-family:var(--mono); }
  button { margin-top:16px; background:var(--accent); color:#06231f; font-weight:700; border:none; cursor:pointer; }
  button:hover { filter:brightness(1.08); }
  button:disabled { opacity:.5; cursor:wait; }
  .panel { margin-top:18px; background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--muted); border-radius:12px; padding:16px 20px; overflow:auto; }
  .panel.good { border-left-color:var(--good); } .panel.warn { border-left-color:var(--warn); }
  .panel.bad { border-left-color:var(--bad); }
  pre { background:#0a0f1d; border:1px solid var(--line); border-radius:10px; padding:12px 14px; overflow:auto; font-family:var(--mono); font-size:12.5px; }
  .big { font-size:15px; }
  .err { color:var(--bad); font-size:13px; margin-top:8px; }
</style>
</head>
<body>
<header>
  <div class="brand">fdie<span>·</span>patch-verifier</div>
  <div id="dbPill" class="pill">db:…</div>
</header>
<main>
  <div class="grid">
    <div class="card span2">
      <h2>Releases <span id="releaseCount" class="muted"></span></h2>
      <table>
        <thead><tr>
          <th>release</th><th>source</th><th>status</th><th class="center">exit</th>
          <th class="center">findings</th><th class="center">secrets</th><th class="center">unchecked</th><th>scanned</th>
        </tr></thead>
        <tbody id="releaseBody"></tbody>
      </table>
      <div id="releaseErr" class="err"></div>
    </div>

    <div class="card">
      <h2>Live scan</h2>
      <label for="fixture">Firmware input (sample fixture in this repo)</label>
      <select id="fixture">
        <option value="fixtures/r1_baseline.tar.gz">r1_baseline.tar.gz (vulnerable baseline)</option>
        <option value="fixtures/r2_fixed.tar.gz">r2_fixed.tar.gz (backported fixes)</option>
        <option value="fixtures/r2_regressed.json">r2_regressed.json (manifest, regressed)</option>
        <option value="fixtures/malformed.json">malformed.json (invalid input)</option>
      </select>
      <label for="scanBaseline">Compare against baseline (optional)</label>
      <select id="scanBaseline"><option value="">— none —</option></select>
      <button id="scanBtn">Run scan</button>
    </div>

    <div class="card">
      <h2>Release-over-release diff</h2>
      <label for="dlBaseline">Baseline release</label>
      <select id="dlBaseline"></select>
      <label for="dlNew">New release</label>
      <select id="dlNew"></select>
      <button id="diffBtn">Compare</button>
    </div>
  </div>

  <div id="scanOut" class="panel"><div class="muted">Run a scan to see its full report here.</div></div>
  <div id="diffOut" class="panel"><div class="muted">Pick a baseline and a new release to see the diff here.</div></div>
</main>

<script>
const $ = (id) => document.getElementById(id);
const STATUS_CLASS = {CLEAN:'good', VULNERABLE:'warn', UNVERIFIED_COVERAGE:'bad', INVALID:'neut'};

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.json();
}

function fillSelect(sel, releases, latestFirst) {
  sel.innerHTML = '';
  const sorted = releases.slice().sort((a, b) => latestFirst ? b.id - a.id : a.id - b.id);
  for (const r of sorted) {
    const opt = document.createElement('option');
    opt.value = r.release_id;
    opt.textContent = r.release_id + '  [' + r.status + '] exit=' + r.exit_code;
    sel.appendChild(opt);
  }
}

function renderReleases(rel) {
  const tb = $('releaseBody');
  tb.innerHTML = '';
  for (const r of rel) {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td class="mono">' + esc(r.release_id) + '</td>' +
      '<td class="mono small">' + esc(r.source_type) + '</td>' +
      '<td><span class="badge ' + (STATUS_CLASS[r.status] || 'neut') + '">' + esc(r.status) + '</span></td>' +
      '<td class="mono center">' + r.exit_code + '</td>' +
      '<td class="center">' + r.finding_count + '</td>' +
      '<td class="center">' + r.secret_count + '</td>' +
      '<td class="center">' + r.unchecked_count + '</td>' +
      '<td class="small mono">' + esc(r.scan_time) + '</td>';
    tb.appendChild(tr);
  }
  $('releaseCount').textContent = rel.length + ' release(s)';
}

async function refreshReleases() {
  try {
    const rel = await api('/releases');
    renderReleases(rel);
    fillSelect($('scanBaseline'), rel, true);
    fillSelect($('dlBaseline'), rel, false);
    fillSelect($('dlNew'), rel, true);
  } catch (e) {
    $('releaseErr').textContent = e.message;
  }
}

async function runScan() {
  const btn = $('scanBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  const out = $('scanOut');
  out.className = 'panel';
  out.innerHTML = '<div class="muted">running scan…</div>';
  try {
    const body = {input: $('fixture').value};
    const bl = $('scanBaseline').value;
    if (bl) body.compare_to = bl;
    const res = await api('/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const oc = res.outcome;
    out.className = 'panel ' + (STATUS_CLASS[oc.status] || 'neut');
    let html = '<h3>Scan result — ' + esc(oc.release_id) + '</h3>' +
      '<p class="big">status <b>' + esc(oc.status) + '</b> · exit code <b>' + oc.exit_code +
      '</b> · files ' + oc.file_count + ' · bytes ' + oc.bytes_total + '</p>' +
      '<pre>' + esc(JSON.stringify(oc, null, 2)) + '</pre>';
    if (res.diff) {
      html += '<h4>Diff vs ' + esc(res.diff.baseline_id) + '</h4>' +
        '<pre>' + esc(JSON.stringify(res.diff, null, 2)) + '</pre>';
    }
    out.innerHTML = html;
    await refreshReleases();
  } catch (e) {
    out.className = 'panel bad';
    out.innerHTML = '<h3>Error</h3><pre>' + esc(e.message) + '</pre>';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run scan';
  }
}

function catTable(title, items, key) {
  if (!items.length) return '<h4>' + title + ' — 0</h4>';
  const rows = items.map(function (i) {
    const id = i[key] || i.path || i.kind || i.cve || i.release_id || '?';
    const kind = i.kind || i.status || '';
    const extra = i.package || i.reason || i.snippet || i.installed_version || '';
    return '<tr><td class="mono">' + esc(id) + '</td><td class="small">' + esc(kind) +
      '</td><td class="small">' + esc(extra) + '</td></tr>';
  }).join('');
  return '<h4>' + title + ' — ' + items.length + '</h4>' +
    '<table><thead><tr><th>id</th><th>kind</th><th>extra</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

async function runDiff() {
  const out = $('diffOut');
  out.className = 'panel';
  const base = $('dlBaseline').value;
  const nw = $('dlNew').value;
  if (!base || !nw) { out.innerHTML = '<div class="muted">select a baseline and a new release</div>'; return; }
  if (base === nw) { out.innerHTML = '<div class="muted">choose two different releases</div>'; return; }
  try {
    const d = await api('/releases/' + encodeURIComponent(nw) + '/diff/' + encodeURIComponent(base));
    const parts = [];
    parts.push('<h3>Diff — ' + esc(base) + ' → ' + esc(nw) + '</h3>');
    parts.push('<p class="big">NEW_EXPOSURE <b>' + d.new_exposure.length + '</b> · ' +
      'NEW_SECRET <b>' + d.new_secret.length + '</b> · ' +
      'NEW_BLIND_SPOT <b>' + d.new_blind_spot.length + '</b> · ' +
      'RESOLVED <b>' + d.resolved.length + '</b></p>');
    parts.push(catTable('New exposures', d.new_exposure, 'cve'));
    parts.push(catTable('New secrets', d.new_secret, 'path'));
    parts.push(catTable('New blind spots', d.new_blind_spot, 'path'));
    parts.push(catTable('Resolved', d.resolved, 'cve'));
    out.innerHTML = parts.join('');
  } catch (e) {
    out.className = 'panel bad';
    out.innerHTML = '<h3>Error</h3><pre>' + esc(e.message) + '</pre>';
  }
}

document.addEventListener('DOMContentLoaded', function () {
  $('scanBtn').addEventListener('click', runScan);
  $('diffBtn').addEventListener('click', runDiff);
  api('/health').then(function (h) {
    $('dbPill').textContent = 'db: ' + h.database;
  }).catch(function () {});
  refreshReleases();
});
</script>
</body>
</html>
"""
