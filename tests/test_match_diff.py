"""Tests for vaultmap.match_diff."""
from __future__ import annotations

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.match_diff import diff_results, diff_summary_lines, DiffReport


def _make_match(path="src/app.py", line=10, pattern="aws_key", value="AKIA1234", severity="high") -> Match:
    return Match(
        path=path,
        line_number=line,
        pattern_name=pattern,
        value=value,
        severity=severity,
        matched_line=f"key = {value}",
    )


def _make_result(matches) -> ScanResult:
    paths = list({m.path for m in matches})
    return ScanResult(matches=matches, scanned_files=paths)


def test_diff_no_changes():
    m = _make_match()
    prev = _make_result([m])
    curr = _make_result([m])
    report = diff_results(prev, curr)
    assert not report.has_new
    assert not report.has_resolved
    assert report.persisted_count == 1


def test_diff_detects_new_match():
    m1 = _make_match(line=1)
    m2 = _make_match(line=2)
    prev = _make_result([m1])
    curr = _make_result([m1, m2])
    report = diff_results(prev, curr)
    assert report.has_new
    assert len(report.new_matches) == 1
    assert report.new_matches[0].line_number == 2
    assert report.persisted_count == 1


def test_diff_detects_resolved_match():
    m1 = _make_match(line=1)
    m2 = _make_match(line=2)
    prev = _make_result([m1, m2])
    curr = _make_result([m1])
    report = diff_results(prev, curr)
    assert report.has_resolved
    assert len(report.resolved_matches) == 1
    assert report.resolved_matches[0].line_number == 2


def test_diff_empty_previous():
    m = _make_match()
    prev = _make_result([])
    curr = _make_result([m])
    report = diff_results(prev, curr)
    assert report.has_new
    assert report.persisted_count == 0


def test_diff_empty_current():
    m = _make_match()
    prev = _make_result([m])
    curr = _make_result([])
    report = diff_results(prev, curr)
    assert report.has_resolved
    assert not report.has_new


def test_summary_string_format():
    report = DiffReport(new_matches=[], resolved_matches=[], persisted_count=5)
    assert "new=0" in report.summary()
    assert "resolved=0" in report.summary()
    assert "persisted=5" in report.summary()


def test_diff_summary_lines_no_change():
    report = DiffReport(new_matches=[], resolved_matches=[], persisted_count=3)
    lines = diff_summary_lines(report)
    assert any("No changes" in l for l in lines)


def test_diff_summary_lines_with_new():
    m = _make_match()
    report = DiffReport(new_matches=[m], resolved_matches=[], persisted_count=0)
    lines = diff_summary_lines(report)
    assert any("[+]" in l for l in lines)
    assert any("aws_key" in l for l in lines)
