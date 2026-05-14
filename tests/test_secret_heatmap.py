"""Tests for vaultmap.secret_heatmap and vaultmap.heatmap_reporter."""
from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from typing import List

import pytest

from vaultmap.secret_heatmap import HeatCell, HeatmapReport, build_heatmap
from vaultmap.heatmap_reporter import print_heatmap_text_report, print_heatmap_json_report


@dataclass
class _FakeMatch:
    path: str
    severity: str
    line: int = 1
    pattern_name: str = "test"
    value: str = "secret"


@dataclass
class _FakeResult:
    matches: List[_FakeMatch] = field(default_factory=list)
    scanned_files: int = 1


def _make_result(*matches: _FakeMatch) -> _FakeResult:
    return _FakeResult(matches=list(matches))


# ── HeatCell ──────────────────────────────────────────────────────────────────

def test_heat_cell_to_dict_keys():
    cell = HeatCell(path="src/app.py", match_count=3, severity_counts={"high": 2, "low": 1})
    d = cell.to_dict()
    assert d["path"] == "src/app.py"
    assert d["match_count"] == 3
    assert d["severity_counts"]["high"] == 2


# ── HeatmapReport ─────────────────────────────────────────────────────────────

def test_heatmap_report_hottest_returns_max():
    cells = [HeatCell("a.py", 1, {}), HeatCell("b.py", 5, {}), HeatCell("c.py", 3, {})]
    report = HeatmapReport(cells=cells)
    assert report.hottest.path == "b.py"


def test_heatmap_report_hottest_empty_returns_none():
    assert HeatmapReport().hottest is None


def test_heatmap_report_total_matches():
    cells = [HeatCell("a.py", 2, {}), HeatCell("b.py", 4, {})]
    assert HeatmapReport(cells=cells).total_matches == 6


def test_heatmap_report_top_limits_output():
    cells = [HeatCell(f"f{i}.py", i, {}) for i in range(10)]
    report = HeatmapReport(cells=cells)
    assert len(report.top(3)) == 3


# ── build_heatmap ─────────────────────────────────────────────────────────────

def test_build_heatmap_empty_result():
    report = build_heatmap(_make_result())
    assert report.total_matches == 0
    assert report.cells == []


def test_build_heatmap_counts_per_file():
    result = _make_result(
        _FakeMatch("src/a.py", "high"),
        _FakeMatch("src/a.py", "low"),
        _FakeMatch("src/b.py", "critical"),
    )
    report = build_heatmap(result)
    by_path = {c.path: c for c in report.cells}
    assert by_path["src/a.py"].match_count == 2
    assert by_path["src/b.py"].match_count == 1


def test_build_heatmap_severity_counts():
    result = _make_result(
        _FakeMatch("app.py", "high"),
        _FakeMatch("app.py", "high"),
        _FakeMatch("app.py", "low"),
    )
    report = build_heatmap(result)
    cell = report.cells[0]
    assert cell.severity_counts["high"] == 2
    assert cell.severity_counts["low"] == 1


def test_build_heatmap_collapse_to_dir():
    result = _make_result(
        _FakeMatch("src/auth/a.py", "high"),
        _FakeMatch("src/auth/b.py", "low"),
        _FakeMatch("src/utils/c.py", "medium"),
    )
    report = build_heatmap(result, collapse_to_dir=True)
    by_path = {c.path: c for c in report.cells}
    assert by_path["src/auth"].match_count == 2
    assert by_path["src/utils"].match_count == 1


# ── reporters ─────────────────────────────────────────────────────────────────

def test_text_report_no_findings_message():
    out = io.StringIO()
    print_heatmap_text_report(HeatmapReport(), out=out)
    assert "No findings" in out.getvalue()


def test_text_report_shows_file_path():
    cells = [HeatCell("secrets/config.py", 3, {"high": 3})]
    out = io.StringIO()
    print_heatmap_text_report(HeatmapReport(cells=cells), out=out)
    assert "secrets/config.py" in out.getvalue()


def test_json_report_structure():
    cells = [HeatCell("a.py", 2, {"low": 2}), HeatCell("b.py", 5, {"critical": 5})]
    out = io.StringIO()
    print_heatmap_json_report(HeatmapReport(cells=cells), out=out)
    data = json.loads(out.getvalue())
    assert "total_matches" in data
    assert "cells" in data
    assert data["total_matches"] == 7


def test_json_report_top_parameter_limits_cells():
    cells = [HeatCell(f"f{i}.py", i + 1, {}) for i in range(10)]
    out = io.StringIO()
    print_heatmap_json_report(HeatmapReport(cells=cells), top=3, out=out)
    data = json.loads(out.getvalue())
    assert len(data["cells"]) == 3
