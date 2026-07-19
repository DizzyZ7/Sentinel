from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.core.version import APP_VERSION
from app.services.local_sarif import build_local_sarif
from app.services.local_scan import (
    EXIT_CONFIGURATION,
    EXIT_SCAN_ERROR,
    LocalScanError,
    build_local_scan_report,
)


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _text_report(report: dict[str, Any], max_display: int) -> str:
    summary = report["summary"]
    baseline = report["baseline"]
    policy = report["policy"]
    mode = report["mode"]
    inventory = report["inventory"]
    lines = [
        f"Sentinel local scan {report['app_version']}",
        f"Repository: {report['repository']}",
        (
            f"Mode: changed files from {mode['base_ref'] or 'working tree'}"
            if mode["changed_only"]
            else "Mode: full supported-source scan"
        ),
        f"Files analyzed: {inventory['selected_file_count']} ({inventory['selected_bytes']} bytes)",
        (
            "Candidates: "
            f"{summary['candidate_count']} total, {baseline['new_count']} new, "
            f"{baseline['existing_count']} existing"
        ),
        (
            "Safety: source_executed=false, dependencies_installed=false, "
            "patches_applied=false, symlinks_followed=false"
        ),
        "",
    ]
    for finding in report["findings"][:max_display]:
        state = "NEW" if finding["baseline_state"] == "new" else "EXISTING"
        lines.append(
            f"[{state}] {finding['static_confidence']:.2f} {finding['rule_id']} "
            f"{finding['file_path']}:{finding['line']} — {finding['title']}"
        )
    hidden = len(report["findings"]) - max_display
    if hidden > 0:
        lines.append(f"... {hidden} additional candidates omitted from console output")
    if not report["findings"]:
        lines.append("No deterministic candidates found in the selected files.")
    lines.extend(
        [
            "",
            (
                f"Policy: BLOCK ({policy['blocker_count']} candidates at confidence "
                f">= {policy['fail_confidence']:.2f})"
                if policy["blocked"]
                else "Policy: PASS"
            ),
            f"Report SHA-256: {report['report_sha256']}",
        ]
    )
    return "\n".join(lines) + "\n"


def _add_scan_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("scan", help="Scan a local repository without executing its source code.")
    parser.add_argument("path", nargs="?", default=".", type=Path)
    parser.add_argument("--changed-only", action="store_true", help="Scan Git-changed and untracked files only.")
    parser.add_argument("--base-ref", help="Compare committed files against this Git base ref.")
    parser.add_argument("--baseline", type=Path, help="Previous Sentinel local JSON report for fingerprint comparison.")
    parser.add_argument("--min-confidence", type=float, default=0.0)
    parser.add_argument("--fail-on", choices=["never", "any", "new"], default="never")
    parser.add_argument("--fail-confidence", type=float, default=0.8)
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-files", type=int, default=5_000)
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", type=Path, help="Write the selected stdout format to a file.")
    parser.add_argument("--json-output", type=Path, help="Also write the complete JSON evidence report.")
    parser.add_argument("--sarif-output", type=Path, help="Also write SARIF 2.1.0 candidates.")
    parser.add_argument("--omit-snippets", action="store_true", help="Omit even sanitized snippets from JSON.")
    parser.add_argument("--max-display", type=int, default=50)
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout when output files are requested.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel local-first security tooling.")
    parser.add_argument("--version", action="version", version=f"Sentinel {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command")
    _add_scan_parser(subparsers)
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    report = build_local_scan_report(
        args.path,
        changed_only=args.changed_only,
        base_ref=args.base_ref,
        baseline=args.baseline,
        min_confidence=args.min_confidence,
        fail_on=args.fail_on,
        fail_confidence=args.fail_confidence,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        include_snippets=not args.omit_snippets,
    )
    sarif = build_local_sarif(report)
    rendered = {
        "text": _text_report(report, max(args.max_display, 0)),
        "json": _json_text(report),
        "sarif": _json_text(sarif),
    }
    if args.output:
        _write(args.output, rendered[args.format])
    if args.json_output:
        _write(args.json_output, rendered["json"])
    if args.sarif_output:
        _write(args.sarif_output, rendered["sarif"])
    outputs_requested = bool(args.output or args.json_output or args.sarif_output)
    if not args.quiet or not outputs_requested:
        sys.stdout.write(rendered[args.format])
    return int(report["policy"]["exit_code"])


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_CONFIGURATION
    try:
        if args.command == "scan":
            return _run_scan(args)
    except LocalScanError as exc:
        print(f"sentinel: configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (OSError, ValueError) as exc:
        print(f"sentinel: scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_SCAN_ERROR
    return EXIT_CONFIGURATION


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
