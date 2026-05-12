"""Tests for vaultmap.severity_report."""
from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from typing import List

from vaultmap.scanner import ScanResult
from vaultmap.severity_report import (
    SeverityBucket,
    SeverityReport,
    build_severity_report,
    print_severity_report,
    _SEVERITY_ORDER,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _FakeMatch:
    path: str = "app/config.py"
    line: int = 1
    pattern_name: str = "aws_access_key"
    value: str = "AKIAIOSFODNN7EXAMPLE"
    severity: str = "high"


def _make_result(matches) -> ScanResult:
    return ScanResult(scanned_files=1, matches=matches)


# ---------------------------------------------------------------------------
# SeverityBucket
# ---------------------------------------------------------------------------

def test_severity_bucket_to_dict_deduplicates_files():
    b = SeverityBucket(severity="high", count=2, files=["a.py", "a.py"], patterns=["p1", "p2"])
    d = b.to_dict()
    assert d["unique_files"] == ["a.py"]
    assert len(d["unique_patterns"]) == 2


# ---------------------------------------------------------------------------
# build_severity_report
# ---------------------------------------------------------------------------

def test_build_severity_report_empty_result():
    result = _make_result([])
    report = build_severity_report(result)
    assert report.total == 0
    assert report.buckets == {}


def test_build_severity_report_single_match():
    result = _make_result([_FakeMatch(severity="critical")])
    report = build_severity_report(result)
    assert report.total == 1
    assert "critical" in report.buckets
    assert report.buckets["critical"].count == 1


def test_build_severity_report_groups_by_severity():
    matches = [
        _FakeMatch(severity="high", path="a.py"),
        _FakeMatch(severity="high", path="b.py"),
        _FakeMatch(severity="low", path="c.py"),
    ]
    report = build_severity_report(_make_result(matches))
    assert report.total == 3
    assert report.buckets["high"].count == 2
    assert report.buckets["low"].count == 1


def test_build_severity_report_normalises_severity_case():
    result = _make_result([_FakeMatch(severity="HIGH")])
    report = build_severity_report(result)
    assert "high" in report.buckets


def test_severity_report_ordered_respects_canonical_order():
    matches = [
        _FakeMatch(severity="low"),
        _FakeMatch(severity="critical"),
        _FakeMatch(severity="medium"),
    ]
    report = build_severity_report(_make_result(matches))
    ordered_sevs = [b.severity for b in report.ordered()]
    assert ordered_sevs.index("critical") < ordered_sevs.index("medium")
    assert ordered_sevs.index("medium") < ordered_sevs.index("low")


def test_severity_report_to_dict_structure():
    result = _make_result([_FakeMatch(severity="high")])
    d = build_severity_report(result).to_dict()
    assert d["total"] == 1
    assert isinstance(d["breakdown"], list)
    assert d["breakdown"][0]["severity"] == "high"


def test_print_severity_report_no_crash(capsys):
    result = _make_result([_FakeMatch(severity="high")])
    print_severity_report(result, use_color=False)
    captured = capsys.readouterr()
    assert "HIGH" in captured.out
    assert "1" in captured.out


def test_print_severity_report_empty_shows_no_findings(capsys):
    print_severity_report(_make_result([]), use_color=False)
    captured = capsys.readouterr()
    assert "No findings" in captured.out
