"""masker_reporter.py — CLI-friendly output for MaskedResult objects."""
from __future__ import annotations

import json
from typing import TextIO
import sys

from vaultmap.secret_masker import MaskedResult

_SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[92m",
}
_RESET = "\033[0m"


def _colorize(text: str, severity: str, *, color: bool) -> str:
    if not color:
        return text
    code = _SEVERITY_COLORS.get(severity.lower(), "")
    return f"{code}{text}{_RESET}" if code else text


def print_masked_text_report(
    result: MaskedResult,
    *,
    out: TextIO = sys.stdout,
    color: bool = True,
) -> None:
    """Print a human-readable report of masked matches."""
    if not result.has_findings():
        out.write("No findings.\n")
        return

    out.write(f"Masked scan report — {len(result)} finding(s)\n")
    out.write("=" * 50 + "\n")
    for mm in result.matches:
        m = mm.original
        severity_label = _colorize(m.severity.upper(), m.severity, color=color)
        out.write(f"[{severity_label}] {m.path}:{m.line}  ({m.pattern})\n")
        out.write(f"  value : {mm.masked_value}  [strategy={mm.strategy}]\n")
    out.write("-" * 50 + "\n")
    out.write(f"Files scanned: {result.files_scanned}\n")


def print_masked_json_report(
    result: MaskedResult,
    *,
    out: TextIO = sys.stdout,
) -> None:
    """Print a JSON report of masked matches."""
    payload = {
        "files_scanned": result.files_scanned,
        "total_findings": len(result),
        "findings": [mm.to_dict() for mm in result.matches],
    }
    json.dump(payload, out, indent=2)
    out.write("\n")
