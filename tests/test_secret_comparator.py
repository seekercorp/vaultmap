"""Tests for vaultmap.secret_comparator and vaultmap.comparison_reporter."""
import io
import json
from unittest.mock import MagicMock

import pytest

from vaultmap.secret_comparator import compare_results, ComparisonReport, ComparedMatch
from vaultmap.comparison_reporter import (
    print_comparison_text_report,
    print_comparison_json_report,
)


def _make_match(path="src/app.py", line=10, pattern="aws_access_key",
                severity="critical", value="AKIAIOSFODNN7EXAMPLE"):
    m = MagicMock()
    m.path = path
    m.line = line
    m.pattern_name = pattern
    m.severity = severity
    m.value = value
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


# ---------------------------------------------------------------------------
# compare_results
# ---------------------------------------------------------------------------

def test_compare_identical_results_all_persisted():
    m = _make_match()
    baseline = _make_result([m])
    current = _make_result([m])
    report = compare_results(baseline, current)
    assert len(report.persisted) == 1
    assert len(report.new) == 0
    assert len(report.resolved) == 0


def test_compare_new_match_detected():
    baseline = _make_result([])
    current = _make_result([_make_match()])
    report = compare_results(baseline, current)
    assert report.has_new
    assert len(report.new) == 1


def test_compare_resolved_match_detected():
    baseline = _make_result([_make_match()])
    current = _make_result([])
    report = compare_results(baseline, current)
    assert report.has_resolved
    assert len(report.resolved) == 1


def test_compare_mixed_changes():
    old_match = _make_match(line=1, value="OLDKEY")
    new_match = _make_match(line=2, value="NEWKEY")
    baseline = _make_result([old_match])
    current = _make_result([new_match])
    report = compare_results(baseline, current)
    assert len(report.new) == 1
    assert len(report.resolved) == 1
    assert len(report.persisted) == 0


def test_summary_counts_are_correct():
    m1 = _make_match(line=1)
    m2 = _make_match(line=2)
    baseline = _make_result([m1])
    current = _make_result([m1, m2])
    report = compare_results(baseline, current)
    s = report.summary()
    assert s["persisted"] == 1
    assert s["new"] == 1
    assert s["resolved"] == 0


def test_to_dict_structure():
    m = _make_match()
    report = compare_results(_make_result([m]), _make_result([m]))
    d = report.to_dict()
    assert "summary" in d
    assert "new" in d
    assert "resolved" in d
    assert "persisted" in d


# ---------------------------------------------------------------------------
# reporters
# ---------------------------------------------------------------------------

def test_text_report_shows_new_heading():
    baseline = _make_result([])
    current = _make_result([_make_match()])
    report = compare_results(baseline, current)
    buf = io.StringIO()
    print_comparison_text_report(report, out=buf, color=False)
    assert "NEW FINDINGS" in buf.getvalue()


def test_text_report_no_changes_message():
    report = ComparisonReport()
    buf = io.StringIO()
    print_comparison_text_report(report, out=buf, color=False)
    assert "No changes" in buf.getvalue()


def test_json_report_is_valid_json():
    m = _make_match()
    report = compare_results(_make_result([m]), _make_result([m]))
    buf = io.StringIO()
    print_comparison_json_report(report, out=buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["persisted"] == 1
