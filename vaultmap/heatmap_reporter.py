"""heatmap_reporter.py — Console and JSON reporters for HeatmapReport."""
from __future__ import annotations

import json
import sys
from typing import TextIO

from vaultmap.reporter import _colorize
from vaultmap.secret_heatmap import HeatmapReport

_SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

_BAR_CHAR = "█"
_BAR_MAX_WIDTH = 30


def _bar(count: int, max_count: int) -> str:
    if max_count == 0:
        return ""
    width = max(1, round(_BAR_MAX_WIDTH * count / max_count))
    return _BAR_CHAR * width


def print_heatmap_text_report(
    report: HeatmapReport,
    top: int = 10,
    out: TextIO = sys.stdout,
) -> None:
    cells = report.top(top)
    if not cells:
        out.write(_colorize("No findings to display in heatmap.\n", "green"))
        return

    max_count = cells[0].match_count
    out.write(_colorize(f"\n{'─' * 60}\n", "cyan"))
    out.write(_colorize(" SECRET HEATMAP\n", "cyan"))
    out.write(_colorize(f"{'─' * 60}\n", "cyan"))
    out.write(f" Total matches : {report.total_matches}\n")
    out.write(f" Files shown   : {len(cells)}\n")
    out.write(_colorize(f"{'─' * 60}\n", "cyan"))

    for cell in cells:
        bar = _bar(cell.match_count, max_count)
        sev_summary = ", ".join(
            f"{_colorize(sev, _SEVERITY_COLORS.get(sev, 'white'))}:{n}"
            for sev, n in sorted(cell.severity_counts.items())
        )
        out.write(f"  {cell.path}\n")
        out.write(f"    [{bar:<{_BAR_MAX_WIDTH}}] {cell.match_count}  {sev_summary}\n")

    out.write(_colorize(f"{'─' * 60}\n", "cyan"))


def print_heatmap_json_report(
    report: HeatmapReport,
    top: int = 10,
    out: TextIO = sys.stdout,
) -> None:
    payload = {
        "total_matches": report.total_matches,
        "cells": [c.to_dict() for c in report.top(top)],
    }
    out.write(json.dumps(payload, indent=2))
    out.write("\n")
