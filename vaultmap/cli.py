"""Command-line interface for vaultmap."""

import argparse
import sys
from pathlib import Path

from vaultmap.scanner import scan_directory, scan_file, has_findings
from vaultmap.git_history import scan_git_history, has_findings as git_has_findings
from vaultmap.reporter import (
    print_text_report,
    print_json_report,
    print_git_text_report,
    print_git_json_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultmap",
        description="Scan codebases and git history for leaked credentials.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--git",
        action="store_true",
        help="Scan git commit history instead of working tree",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Filter results to a minimum severity level",
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=100,
        dest="max_commits",
        help="Maximum number of commits to scan in git mode (default: 100)",
    )
    return parser


_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _severity_filter(severity: str):
    """Return a callable that keeps matches at or above *severity*."""
    min_index = _SEVERITY_ORDER.index(severity)

    def _keep(match) -> bool:
        try:
            return _SEVERITY_ORDER.index(match.severity) >= min_index
        except (AttributeError, ValueError):
            return True

    return _keep


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path)

    if args.git:
        result = scan_git_history(target, max_commits=args.max_commits)
        if args.severity:
            keep = _severity_filter(args.severity)
            result = result._replace(
                matches=[m for m in result.matches if keep(m)]
            )
        if args.format == "json":
            print_git_json_report(result)
        else:
            print_git_text_report(result)
        return 1 if git_has_findings(result) else 0

    if target.is_file():
        result = scan_file(target)
    else:
        result = scan_directory(target)

    if args.severity:
        keep = _severity_filter(args.severity)
        filtered = {k: [m for m in v if keep(m)] for k, v in result.matches_by_file.items()}
        result = result._replace(matches_by_file=filtered)

    if args.format == "json":
        print_json_report(result)
    else:
        print_text_report(result)

    return 1 if has_findings(result) else 0


if __name__ == "__main__":
    sys.exit(main())
