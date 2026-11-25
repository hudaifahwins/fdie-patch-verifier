"""Command-line interface for fdie-patch-verifier (entry point: ``fdie-verify``)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .models import DiffReport, VerificationOutcome, VulnerabilityStatus
from .verifier import InvalidInputError, perform_verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fdie-verify",
        description=(
            "Verify firmware archives/manifests for vulnerabilities, secrets and "
            "coverage gaps; persist history to SQLite; diff against a baseline."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        help="JSON manifest or .tar.gz/.zip firmware bundle to verify",
    )
    parser.add_argument(
        "--db",
        default="verifier.sqlite",
        help="SQLite database path (default: verifier.sqlite)",
    )
    parser.add_argument(
        "--compare-to",
        metavar="BASELINE_ID",
        default=None,
        help="baseline release_id for a release-over-release diff",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="write the report to this file instead of stdout",
    )
    return parser


def render_text(outcome: VerificationOutcome, diff: DiffReport | None) -> str:
    lines = [
        "fdie-patch-verifier report",
        f"  release      : {outcome.release_id}",
        f"  source       : {outcome.source} ({outcome.source_type})",
        f"  status       : {outcome.status.value}",
        f"  exit code    : {outcome.exit_code}",
        f"  scanned files: {outcome.file_count} ({outcome.bytes_total} bytes)",
        f"  scan time    : {outcome.scan_time}",
    ]
    if outcome.findings:
        lines.append("")
        lines.append("Findings:")
        for f in outcome.findings:
            mark = (
                "[VULN]"
                if f.status is VulnerabilityStatus.CONFIRMED_VULNERABLE
                else "[BACKPORTED]"
            )
            lines.append(f"  {mark} {f.cve} {f.package} {f.installed_version or ''} ({f.severity.value})")
            if f.evidence:
                lines.append(f"        {f.evidence}")
    if outcome.secrets:
        lines.append("")
        lines.append("Secrets:")
        for s in outcome.secrets:
            lines.append(f"  [{s.kind.value}] {s.path}:{s.line or '-'} {s.snippet}")
    if outcome.unchecked_regions:
        lines.append("")
        lines.append("Unchecked regions:")
        for u in outcome.unchecked_regions:
            lines.append(f"  [{u.kind.value}] {u.path or '-'}: {u.reason}")
    if diff is not None:
        lines.append("")
        lines.append(f"Diff vs baseline '{diff.baseline_id}':")
        lines.append(f"  NEW_EXPOSURE   : {len(diff.new_exposure)}")
        for f in diff.new_exposure:
            lines.append(f"      + {f.cve} ({f.package} {f.installed_version or ''})")
        lines.append(f"  NEW_SECRET     : {len(diff.new_secret)}")
        for s in diff.new_secret:
            lines.append(f"      + {s.path} ({s.kind.value})")
        lines.append(f"  NEW_BLIND_SPOT : {len(diff.new_blind_spot)}")
        for u in diff.new_blind_spot:
            lines.append(f"      + {u.path or '-'} ({u.kind.value})")
        lines.append(f"  RESOLVED       : {len(diff.resolved)}")
        for f in diff.resolved:
            lines.append(f"      - {f.cve} ({f.package})")
    return "\n".join(lines)


def render_json(outcome: VerificationOutcome, diff: DiffReport | None) -> str:
    payload = {
        "outcome": outcome.model_dump(),
        "diff": diff.model_dump() if diff is not None else None,
    }
    return json.dumps(payload, indent=2)


def render_markdown(outcome: VerificationOutcome, diff: DiffReport | None) -> str:
    md = [
        f"# fdie-patch-verifier — {outcome.release_id}",
        "",
        f"- **Source:** `{outcome.source}` ({outcome.source_type})",
        f"- **Status:** `{outcome.status.value}` — exit code **{outcome.exit_code}**",
        f"- **Files scanned:** {outcome.file_count} ({outcome.bytes_total} bytes)",
        f"- **Scan time:** {outcome.scan_time}",
    ]
    if outcome.findings:
        md += ["", "## Findings", "", "| Status | CVE | Package | Installed | Severity | Evidence |", "|---|---|---|---|---|---|"]
        for f in outcome.findings:
            md.append(
                f"| {f.status.value} | {f.cve} | {f.package} | "
                f"{f.installed_version or '-'} | {f.severity.value} | "
                f"{f.evidence or ''} |"
            )
    if outcome.secrets:
        md += ["", "## Secrets", "", "| Kind | Path | Line | Snippet |", "|---|---|---|---|"]
        for s in outcome.secrets:
            md.append(f"| {s.kind.value} | {s.path} | {s.line or '-'} | `{s.snippet}` |")
    if outcome.unchecked_regions:
        md += ["", "## Unchecked regions", "", "| Kind | Path | Reason |", "|---|---|---|"]
        for u in outcome.unchecked_regions:
            md.append(f"| {u.kind.value} | {u.path or '-'} | {u.reason} |")
    if diff is not None:
        md += [
            "",
            f"## Diff vs baseline `{diff.baseline_id}`",
            "",
            f"- **NEW_EXPOSURE:** {len(diff.new_exposure)}",
            f"- **NEW_SECRET:** {len(diff.new_secret)}",
            f"- **NEW_BLIND_SPOT:** {len(diff.new_blind_spot)}",
            f"- **RESOLVED:** {len(diff.resolved)}",
        ]
        if diff.new_exposure:
            md += ["", "### New exposures"]
            for f in diff.new_exposure:
                md.append(f"- `{f.cve}` in `{f.package}` ({f.installed_version or '?'})")
        if diff.new_secret:
            md += ["", "### New secrets"]
            for s in diff.new_secret:
                md.append(f"- `{s.path}` ({s.kind.value})")
        if diff.new_blind_spot:
            md += ["", "### New blind spots"]
            for u in diff.new_blind_spot:
                md.append(f"- `{u.path or '-'}` ({u.kind.value}) — {u.reason}")
        if diff.resolved:
            md += ["", "### Resolved"]
            for f in diff.resolved:
                md.append(f"- `{f.cve}` in `{f.package}`")
    return "\n".join(md)


_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        outcome, diff = perform_verification(args.input, args.db, args.compare_to)
    except InvalidInputError as exc:
        if args.format == "json":
            text = json.dumps({"error": str(exc)}, indent=2)
        else:
            text = f"ERROR: {exc}"
        _emit(text, args.output)
        return 2
    text = _RENDERERS[args.format](outcome, diff)
    _emit(text, args.output)
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
