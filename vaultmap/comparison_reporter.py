"""Render ComparisonReport to text or JSON."""
from __future__ import annotations

import json
import sys
from typing import TextIO

from vaultmap.secret_comparator import ComparisonReport
from vaultmap.reporter import _colorize


_STATUS_COLORS = {
    "new": "red",
    "resolved": "green",
    "persisted": "yellow",
}


def print_comparison_text_report(
    report: ComparisonReport,
    out: TextIO = sys.stdout,
    color: bool = True,
) -> None:
    summary = report.summary()
    out.write("=== Scan Comparison ===\n")
    out.write(
        f"  new: {summary['new']}  "
        f"resolved: {summary['resolved']}  "
        f"persisted: {summary['persisted']}\n"
    )
    out.write("\n")

    sections = [
        ("NEW FINDINGS", report.new),
        ("RESOLVED FINDINGS", report.resolved),
        ("PERSISTED FINDINGS", report.persisted),
    ]

    for heading, items in sections:
        if not items:
            continue
        status = items[0].status
        clr = _STATUS_COLORS.get(status, "white")
        label = _colorize(f"[{heading}]", clr) if color else f"[{heading}]"
        out.write(f"{label}\n")
        for cm in items:
            m = cm.match
            line = f"  {m.path}:{m.line}  [{m.severity}]  {m.pattern_name}  {m.value}\n"
            out.write(line)
        out.write("\n")

    if not report.has_new and not report.has_resolved:
        out.write("No changes detected between scans.\n")


def print_comparison_json_report(
    report: ComparisonReport,
    out: TextIO = sys.stdout,
) -> None:
    json.dump(report.to_dict(), out, indent=2)
    out.write("\n")
