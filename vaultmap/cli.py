"""Command-line interface for vaultmap."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from vaultmap.allowlist import Allowlist, load_allowlist
from vaultmap.audit_log import log_git_scan, log_scan
from vaultmap.baseline import filter_new_matches, load_baseline, save_baseline
from vaultmap.deduplicator import deduplicate_result
from vaultmap.git_history import scan_git_history
from vaultmap.output_formatter import print_sarif_report, print_summary_report
from vaultmap.redactor import redact_result
from vaultmap.reporter import (
    print_git_json_report,
    print_git_text_report,
    print_json_report,
    print_text_report,
)
from vaultmap.scanner import Match, ScanResult, scan_directory, scan_file
from vaultmap.suppression import filter_suppressed


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vaultmap",
        description="Lightweight secret scanner for local codebases and git history.",
    )
    sub = p.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Scan files or directories.")
    scan_p.add_argument("path", type=Path)
    scan_p.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    scan_p.add_argument("--format", dest="fmt", choices=["text", "json", "sarif", "summary"], default="text")
    scan_p.add_argument("--redact", action="store_true")
    scan_p.add_argument("--dedup", action="store_true")
    scan_p.add_argument("--baseline", type=Path)
    scan_p.add_argument("--save-baseline", type=Path, dest="save_baseline")
    scan_p.add_argument("--allowlist", type=Path)
    scan_p.add_argument("--no-audit", action="store_true")

    # ── git ───────────────────────────────────────────────────────────────
    git_p = sub.add_parser("git", help="Scan git history.")
    git_p.add_argument("repo", type=Path)
    git_p.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    git_p.add_argument("--format", dest="fmt", choices=["text", "json"], default="text")
    git_p.add_argument("--no-audit", action="store_true")

    # ── watch ─────────────────────────────────────────────────────────────
    watch_p = sub.add_parser("watch", help="Watch a directory for new secrets in real time.")
    watch_p.add_argument("path", type=Path)
    watch_p.add_argument("--interval", type=float, default=2.0)
    watch_p.add_argument("--baseline", type=Path)
    watch_p.add_argument("--ext", type=str, default=None, help="Comma-separated extensions, e.g. py,env")
    watch_p.add_argument("--format", dest="fmt", choices=["text", "json"], default="text")

    return p


def _severity_filter(severity: Optional[str]):
    order = ["low", "medium", "high", "critical"]
    if severity is None:
        return lambda m: True
    threshold = order.index(severity)
    return lambda m: order.index(m.severity) >= threshold


def _keep(matches: List[Match], severity: Optional[str]) -> List[Match]:
    return [m for m in matches if _severity_filter(severity)(m)]


def _keep(result: ScanResult, severity: Optional[str]) -> ScanResult:  # type: ignore[misc]
    from vaultmap.scanner import ScanResult as SR
    filtered = [m for m in result.matches if _severity_filter(severity)(m)]
    return SR(matches=filtered, files_scanned=result.files_scanned)


def _watch_on_finding_text(path: Path, matches) -> None:
    from vaultmap.reporter import _colorize
    print(_colorize(f"[WATCH] {path}", "red"))
    for m in matches:
        print(f"  line {m.line_number}: [{m.severity}] {m.pattern_name}  {m.value}")


def _watch_on_finding_json(path: Path, matches) -> None:
    import json
    print(json.dumps({"file": str(path), "matches": [vars(m) for m in matches]}))


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        p: Path = args.path
        result = scan_file(p) if p.is_file() else scan_directory(p)
        result = _keep(result, args.severity)
        if args.dedup:
            result = deduplicate_result(result)
        if args.baseline and args.baseline.exists():
            known = load_baseline(args.baseline)
            result.matches = filter_new_matches(result.matches, known)
        if args.allowlist and args.allowlist.exists():
            al = load_allowlist(args.allowlist)
            result.matches = [m for m in result.matches if not al.is_allowed(m)]
        if args.redact:
            result = redact_result(result)
        if args.save_baseline:
            from vaultmap.baseline import _fingerprint
            fps = {_fingerprint(m) for m in result.matches}
            save_baseline(fps, args.save_baseline)
        if not args.no_audit:
            log_scan(result, str(p))
        fmt = args.fmt
        if fmt == "json":
            print_json_report(result)
        elif fmt == "sarif":
            print_sarif_report(result)
        elif fmt == "summary":
            print_summary_report(result)
        else:
            print_text_report(result)
        return 1 if result.matches else 0

    elif args.command == "git":
        git_result = scan_git_history(args.repo)
        if not args.no_audit:
            log_git_scan(git_result, str(args.repo))
        if args.fmt == "json":
            print_git_json_report(git_result)
        else:
            print_git_text_report(git_result)
        return 1 if git_result.has_findings() else 0

    elif args.command == "watch":
        from vaultmap.watchdog import watch
        extensions = None
        if args.ext:
            extensions = {f".{e.lstrip('.')}" for e in args.ext.split(",")}
        on_finding = _watch_on_finding_json if args.fmt == "json" else _watch_on_finding_text
        try:
            watch(
                root=args.path,
                on_finding=on_finding,
                interval=args.interval,
                baseline_path=args.baseline,
                extensions=extensions,
            )
        except KeyboardInterrupt:
            pass
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
