"""Reporting utilities for scan results."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vaultmap.scanner import ScanResult
    from vaultmap.git_history import GitScanResult

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[96m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    code = _COLORS.get(color, "")
    return f"{code}{text}{_COLORS['reset']}"


def print_text_report(result: "ScanResult") -> None:
    """Print a human-readable report for a filesystem scan."""
    print(_colorize(f"\nVaultMap Scan — {result.root_path}", "bold"))
    print(f"  Files scanned : {result.files_scanned}")
    print(f"  Total matches : {result.total_matches}")
    if not result.has_findings:
        print(_colorize("  ✓ No credentials found.", "low"))
        return
    for match in sorted(result.matches, key=lambda m: m.severity):
        sev = _colorize(match.severity.upper(), match.severity)
        print(f"  [{sev}] {match.file}:{match.line_number}  {match.pattern_name}")
        print(f"         {match.line_content[:120]}")


def print_json_report(result: "ScanResult") -> None:
    """Print a JSON report for a filesystem scan."""
    data = {
        "root_path": result.root_path,
        "files_scanned": result.files_scanned,
        "total_matches": result.total_matches,
        "matches": [
            {
                "file": m.file,
                "line_number": m.line_number,
                "pattern_name": m.pattern_name,
                "severity": m.severity,
                "line_content": m.line_content,
            }
            for m in result.matches
        ],
    }
    print(json.dumps(data, indent=2))


def print_git_text_report(result: "GitScanResult") -> None:
    """Print a human-readable report for a git-history scan."""
    print(_colorize(f"\nVaultMap Git History Scan — {result.repo_path}", "bold"))
    print(f"  Commits scanned : {result.commits_scanned}")
    print(f"  Total matches   : {result.total_matches}")
    if not result.has_findings:
        print(_colorize("  ✓ No credentials found in git history.", "low"))
        return
    for cm in result.commit_matches:
        print(_colorize(f"\n  Commit {cm.commit_hash[:12]}  {cm.commit_message[:72]}", "bold"))
        for match in cm.matches:
            sev = _colorize(match.severity.upper(), match.severity)
            print(f"    [{sev}] {match.file}  {match.pattern_name}")
            print(f"           {match.line_content[:120]}")


def print_git_json_report(result: "GitScanResult") -> None:
    """Print a JSON report for a git-history scan."""
    data = {
        "repo_path": result.repo_path,
        "commits_scanned": result.commits_scanned,
        "total_matches": result.total_matches,
        "commit_matches": [
            {
                "commit_hash": cm.commit_hash,
                "commit_message": cm.commit_message,
                "matches": [
                    {
                        "file": m.file,
                        "line_number": m.line_number,
                        "pattern_name": m.pattern_name,
                        "severity": m.severity,
                        "line_content": m.line_content,
                    }
                    for m in cm.matches
                ],
            }
            for cm in result.commit_matches
        ],
    }
    print(json.dumps(data, indent=2))
