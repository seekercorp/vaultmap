"""Command-line interface for vaultmap."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from vaultmap import scanner, git_history, reporter, output_formatter
from vaultmap.allowlist import Allowlist
from vaultmap.baseline import load_baseline, filter_new_matches
from vaultmap.audit_log import log_scan, log_git_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vaultmap",
        description="Lightweight secret scanning utility.",
    )
    sub = p.add_subparsers(dest="command")

    # --- scan subcommand ---
    scan_p = sub.add_parser("scan", help="Scan a local directory.")
    scan_p.add_argument("path", type=Path, help="Directory to scan.")
    scan_p.add_argument("--severity", default="low",
                        choices=["low", "medium", "high", "critical"],
                        help="Minimum severity to report.")
    scan_p.add_argument("--format", dest="fmt", default="text",
                        choices=["text", "json", "sarif"],
                        help="Output format.")
    scan_p.add_argument("--allowlist", type=Path, default=None,
                        help="Path to allowlist YAML file.")
    scan_p.add_argument("--baseline", type=Path, default=None,
                        help="Baseline file; only report new findings.")
    scan_p.add_argument("--audit-log", dest="audit_log", default=None,
                        help="Append scan summary to this JSONL file.")

    # --- git-scan subcommand ---
    git_p = sub.add_parser("git-scan", help="Scan git commit history.")
    git_p.add_argument("path", type=Path, nargs="?", default=Path("."),
                       help="Repository path (default: current directory).")
    git_p.add_argument("--severity", default="low",
                        choices=["low", "medium", "high", "critical"])
    git_p.add_argument("--format", dest="fmt", default="text",
                        choices=["text", "json"])
    git_p.add_argument("--audit-log", dest="audit_log", default=None,
                        help="Append scan summary to this JSONL file.")

    return p


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_filter(minimum: str):
    min_rank = _SEVERITY_RANK[minimum]
    def _keep(match) -> bool:
        return _SEVERITY_RANK.get(match.severity, 0) >= min_rank
    return _keep


def _keep(match, minimum: str) -> bool:  # kept for backward-compat with tests
    return _severity_filter(minimum)(match)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    keep = _severity_filter(args.severity)

    if args.command == "scan":
        allowlist = Allowlist.from_file(args.allowlist) if args.allowlist else Allowlist([])
        baseline = load_baseline(args.baseline) if args.baseline else set()

        result = scanner.scan_directory(args.path)

        # Apply severity + allowlist + baseline filters
        filtered: dict = {}
        for file_path, matches in result.matches.items():
            kept = [
                m for m in matches
                if keep(m)
                and not allowlist.is_allowed(m)
            ]
            kept = filter_new_matches(kept, baseline)
            if kept:
                filtered[file_path] = kept
        result = scanner.ScanResult(scanned_files=result.scanned_files, matches=filtered)

        log_scan(result, log_file=args.audit_log)

        if args.fmt == "json":
            reporter.print_json_report(result)
        elif args.fmt == "sarif":
            output_formatter.print_sarif_report(result)
        else:
            reporter.print_text_report(result)

        return 1 if scanner.has_findings(result) else 0

    if args.command == "git-scan":
        result = git_history.scan_git_history(args.path)

        # Severity filter
        filtered_commits = []
        for cm in result.commit_matches:
            kept = [m for m in cm.matches if keep(m)]
            filtered_commits.append(
                git_history.CommitMatch(
                    commit_hash=cm.commit_hash,
                    author=cm.author,
                    date=cm.date,
                    message=cm.message,
                    matches=kept,
                )
            )
        result = git_history.GitScanResult(commit_matches=filtered_commits)

        log_git_scan(result, log_file=args.audit_log)

        if args.fmt == "json":
            reporter.print_git_json_report(result)
        else:
            reporter.print_git_text_report(result)

        return 1 if git_history.has_findings(result) else 0

    return 0
