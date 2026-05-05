"""Output formatting and reporting for scan results."""

import json
from typing import TextIO
import sys

from vaultmap.scanner import ScanResult, Match

SEVERITY_COLORS = {
    "high": "\033[91m",    # red
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",     # blue
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _colorize(text: str, severity: str, use_color: bool) -> str:
    if not use_color:
        return text
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}"


def print_text_report(result: ScanResult, out: TextIO = sys.stdout, use_color: bool = True) -> None:
    """Print a human-readable report to the given output stream."""
    out.write(f"\n{BOLD}VaultMap Scan Report{RESET}\n" if use_color else "\nVaultMap Scan Report\n")
    out.write(f"Files scanned : {result.scanned_files}\n")
    out.write(f"Total findings: {len(result.matches)}\n\n")

    if not result.has_findings:
        out.write("No secrets found.\n")
        return

    for severity in ("high", "medium", "low"):
        findings = result.by_severity(severity)
        if not findings:
            continue
        label = _colorize(f"[{severity.upper()}]", severity, use_color)
        out.write(f"{label} {len(findings)} finding(s)\n")
        for match in findings:
            out.write(f"  {match.file_path}:{match.line_number}\n")
            out.write(f"    Pattern : {match.pattern.description}\n")
            out.write(f"    Match   : {match.matched_text[:80]}\n")
            out.write(f"    Context : {match.line_content[:100]}\n\n")


def print_json_report(result: ScanResult, out: TextIO = sys.stdout) -> None:
    """Print a JSON-formatted report."""
    data = {
        "scanned_files": result.scanned_files,
        "total_findings": len(result.matches),
        "findings": [
            {
                "file": m.file_path,
                "line": m.line_number,
                "pattern": m.pattern.name,
                "severity": m.pattern.severity,
                "description": m.pattern.description,
                "matched_text": m.matched_text,
            }
            for m in result.matches
        ],
    }
    json.dump(data, out, indent=2)
    out.write("\n")
