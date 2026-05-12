"""Renders GroupedReport objects to the terminal or as JSON."""

from __future__ import annotations

import json
from typing import TextIO
import sys

from vaultmap.reporter import _colorize
from vaultmap.secret_grouper import GroupedReport

_SEVERITY_COLORS = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

_STRATEGY_LABELS = {
    "pattern": "Pattern",
    "file": "File",
    "severity": "Severity",
}


def print_grouped_text_report(
    report: GroupedReport,
    out: TextIO = sys.stdout,
    use_color: bool = True,
) -> None:
    """Print a human-readable grouped summary table."""
    label = _STRATEGY_LABELS.get(report.strategy, report.strategy.title())
    header = f"Grouped by {label}  ({report.total} total match(es))"
    out.write(header + "\n")
    out.write("-" * len(header) + "\n")

    if not report.groups:
        out.write("  No findings.\n")
        return

    col_width = max(len(g.key) for g in report.groups) + 2

    for group in report.groups:
        color = _SEVERITY_COLORS.get(group.key) if report.strategy == "severity" else None
        key_str = group.key.ljust(col_width)
        if color and use_color:
            key_str = _colorize(key_str, color)

        file_summary = ", ".join(group.files[:3])
        if len(group.files) > 3:
            file_summary += f" (+{len(group.files) - 3} more)"

        count_str = str(group.count).rjust(4)
        out.write(f"  {key_str}  {count_str} match(es)  [{file_summary}]\n")

    out.write("\n")


def print_grouped_json_report(
    report: GroupedReport,
    out: TextIO = sys.stdout,
) -> None:
    """Emit the grouped report as a JSON object."""
    json.dump(report.to_dict(), out, indent=2)
    out.write("\n")
