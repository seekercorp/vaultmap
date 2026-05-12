"""Tests for vaultmap.secret_grouper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.secret_grouper import (
    GroupedReport,
    MatchGroup,
    group_by_file,
    group_by_pattern,
    group_by_severity,
)


def _make_match(path: str, pattern_name: str, severity: str, line: int = 1) -> Match:
    return Match(
        path=path,
        line=line,
        pattern_name=pattern_name,
        severity=severity,
        value="secret",
        context=f"context line {line}",
    )


def _make_result(matches: List[Match]) -> ScanResult:
    paths = sorted({m.path for m in matches})
    return ScanResult(files_scanned=paths, matches=matches)


# ---------------------------------------------------------------------------
# MatchGroup
# ---------------------------------------------------------------------------

def test_match_group_count():
    g = MatchGroup(key="aws", matches=[_make_match("a.py", "aws", "high")])
    assert g.count == 1


def test_match_group_files_deduplicated():
    m1 = _make_match("a.py", "aws", "high", line=1)
    m2 = _make_match("a.py", "aws", "high", line=2)
    g = MatchGroup(key="aws", matches=[m1, m2])
    assert g.files == ["a.py"]


def test_match_group_to_dict():
    g = MatchGroup(key="github", matches=[_make_match("b.py", "github", "medium")])
    d = g.to_dict()
    assert d["key"] == "github"
    assert d["count"] == 1
    assert d["files"] == ["b.py"]


# ---------------------------------------------------------------------------
# GroupedReport
# ---------------------------------------------------------------------------

def test_grouped_report_total():
    g1 = MatchGroup(key="a", matches=[_make_match("x.py", "a", "high")])
    g2 = MatchGroup(key="b", matches=[_make_match("y.py", "b", "low"), _make_match("z.py", "b", "low")])
    report = GroupedReport(strategy="pattern", groups=[g1, g2])
    assert report.total == 3


def test_grouped_report_get_existing():
    g = MatchGroup(key="aws", matches=[])
    report = GroupedReport(strategy="pattern", groups=[g])
    assert report.get("aws") is g


def test_grouped_report_get_missing_returns_none():
    report = GroupedReport(strategy="pattern", groups=[])
    assert report.get("nonexistent") is None


# ---------------------------------------------------------------------------
# group_by_pattern
# ---------------------------------------------------------------------------

def test_group_by_pattern_keys():
    matches = [
        _make_match("a.py", "aws", "high"),
        _make_match("b.py", "github", "medium"),
        _make_match("c.py", "aws", "high"),
    ]
    report = group_by_pattern(_make_result(matches))
    assert report.strategy == "pattern"
    keys = [g.key for g in report.groups]
    assert sorted(keys) == ["aws", "github"]
    assert report.get("aws").count == 2


# ---------------------------------------------------------------------------
# group_by_file
# ---------------------------------------------------------------------------

def test_group_by_file_keys():
    matches = [
        _make_match("a.py", "aws", "high"),
        _make_match("a.py", "github", "medium"),
        _make_match("b.py", "aws", "high"),
    ]
    report = group_by_file(_make_result(matches))
    assert report.strategy == "file"
    assert report.get("a.py").count == 2
    assert report.get("b.py").count == 1


# ---------------------------------------------------------------------------
# group_by_severity
# ---------------------------------------------------------------------------

def test_group_by_severity_ordering():
    matches = [
        _make_match("a.py", "p", "low"),
        _make_match("b.py", "p", "high"),
        _make_match("c.py", "p", "medium"),
    ]
    report = group_by_severity(_make_result(matches))
    assert report.strategy == "severity"
    keys = [g.key for g in report.groups]
    assert keys == ["high", "medium", "low"]


def test_group_by_severity_empty_result():
    report = group_by_severity(_make_result([]))
    assert report.total == 0
    assert report.groups == []
