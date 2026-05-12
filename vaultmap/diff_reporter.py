"""diff_reporter.py – print DiffReport to stdout as text or JSON."""
from __future__ import annotations

import json
from typing import TextIO
import sys

from vaultmap.match_diff import DiffReport, diff_summary_lines
from vaultmap.reporter import _colorize


def _match_to_dict(m) -> dict:
    return {
        "path": m.path,
        "line_number": m.line_number,
        "pattern_name": m.pattern_name,
        "severity": m.severity,
        "value": m.value,
    }


def print_diff_text_report(
    report: DiffReport,
    out: TextIO = sys.stdout,
    use_color: bool = True,
) -> None:
    """Render a human-readable diff report."""
    title = "=== Scan Diff ==="
    out.write((_colorize(title, "cyan") if use_color else title) + "\n")
    for line in diff_summary_lines(report):
        if line.startswith("  [+]") and use_color:
            out.write(_colorize(line, "red") + "\n")
        elif line.startswith("  [-]") and use_color:
            out.write(_colorize(line, "green") + "\n")
        else:
            out.write(line + "\n")


def print_diff_json_report(
    report: DiffReport,
    out: TextIO = sys.stdout,
) -> None:
    """Render a machine-readable JSON diff report."""
    payload = {
        "new": [_match_to_dict(m) for m in report.new_matches],
        "resolved": [_match_to_dict(m) for m in report.resolved_matches],
        "persisted_count": report.persisted_count,
        "summary": report.summary(),
    }
    out.write(json.dumps(payload, indent=2) + "\n")
