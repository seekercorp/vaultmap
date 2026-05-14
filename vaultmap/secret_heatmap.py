"""secret_heatmap.py — Builds a heatmap of credential density across files and directories."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from vaultmap.scanner import ScanResult


@dataclass
class HeatCell:
    path: str
    match_count: int
    severity_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "match_count": self.match_count,
            "severity_counts": self.severity_counts,
        }


@dataclass
class HeatmapReport:
    cells: List[HeatCell] = field(default_factory=list)

    @property
    def hottest(self) -> HeatCell | None:
        return max(self.cells, key=lambda c: c.match_count, default=None)

    @property
    def total_matches(self) -> int:
        return sum(c.match_count for c in self.cells)

    def top(self, n: int = 5) -> List[HeatCell]:
        return sorted(self.cells, key=lambda c: c.match_count, reverse=True)[:n]

    def to_dict(self) -> dict:
        return {
            "total_matches": self.total_matches,
            "cells": [c.to_dict() for c in self.top()],
        }


def build_heatmap(result: ScanResult, collapse_to_dir: bool = False) -> HeatmapReport:
    """Aggregate match counts per file (or parent directory when *collapse_to_dir* is True)."""
    counts: Dict[str, int] = defaultdict(int)
    severity_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for match in result.matches:
        key = str(Path(match.path).parent) if collapse_to_dir else match.path
        counts[key] += 1
        severity_counts[key][match.severity] += 1

    cells = [
        HeatCell(
            path=path,
            match_count=count,
            severity_counts=dict(severity_counts[path]),
        )
        for path, count in counts.items()
    ]
    cells.sort(key=lambda c: c.match_count, reverse=True)
    return HeatmapReport(cells=cells)
