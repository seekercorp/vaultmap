"""Tests for vaultmap.secret_profiler."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultmap.secret_profiler import (
    PatternProfile,
    ProfileReport,
    build_profile_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(
    pattern_name: str = "aws_access_key",
    severity: str = "critical",
    path: str = "src/config.py",
    line_number: int = 10,
    entropy: float | None = 3.8,
) -> MagicMock:
    m = MagicMock()
    m.pattern_name = pattern_name
    m.severity = severity
    m.path = path
    m.line_number = line_number
    m.entropy = entropy
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


# ---------------------------------------------------------------------------
# PatternProfile.to_dict
# ---------------------------------------------------------------------------

def test_pattern_profile_to_dict_keys():
    profile = PatternProfile(pattern_name="aws_access_key", severity="critical")
    profile.occurrences = 2
    profile.affected_files = ["a.py", "b.py"]
    profile.avg_entropy = 3.9
    profile.sample_line = 5
    d = profile.to_dict()
    assert set(d.keys()) == {"pattern_name", "severity", "occurrences", "unique_files", "avg_entropy", "sample_line"}


def test_pattern_profile_unique_files_deduplicates():
    profile = PatternProfile(pattern_name="x", severity="high")
    profile.affected_files = ["a.py", "a.py", "b.py"]
    assert profile.to_dict()["unique_files"] == 2


# ---------------------------------------------------------------------------
# build_profile_report
# ---------------------------------------------------------------------------

def test_build_profile_report_empty_result():
    result = _make_result([])
    report = build_profile_report(result)
    assert report.profiles == {}


def test_build_profile_report_single_match():
    match = _make_match()
    report = build_profile_report(_make_result([match]))
    assert "aws_access_key" in report.profiles
    profile = report.profiles["aws_access_key"]
    assert profile.occurrences == 1
    assert profile.severity == "critical"


def test_build_profile_report_aggregates_occurrences():
    matches = [_make_match(path="a.py"), _make_match(path="b.py")]
    report = build_profile_report(_make_result(matches))
    assert report.profiles["aws_access_key"].occurrences == 2


def test_build_profile_report_avg_entropy_computed():
    matches = [
        _make_match(entropy=2.0),
        _make_match(entropy=4.0),
    ]
    report = build_profile_report(_make_result(matches))
    assert report.profiles["aws_access_key"].avg_entropy == pytest.approx(3.0)


def test_build_profile_report_no_entropy_leaves_none():
    match = _make_match(entropy=None)
    report = build_profile_report(_make_result([match]))
    assert report.profiles["aws_access_key"].avg_entropy is None


def test_build_profile_report_multiple_patterns():
    matches = [
        _make_match(pattern_name="aws_access_key", severity="critical"),
        _make_match(pattern_name="github_token", severity="high"),
    ]
    report = build_profile_report(_make_result(matches))
    assert len(report.profiles) == 2


# ---------------------------------------------------------------------------
# ProfileReport helpers
# ---------------------------------------------------------------------------

def test_top_by_occurrences_returns_sorted():
    matches = (
        [_make_match(pattern_name="aws_access_key")] * 3
        + [_make_match(pattern_name="github_token", severity="high")] * 1
    )
    report = build_profile_report(_make_result(matches))
    top = report.top_by_occurrences(n=2)
    assert top[0].pattern_name == "aws_access_key"
    assert top[0].occurrences == 3


def test_by_severity_filters_correctly():
    matches = [
        _make_match(pattern_name="aws_access_key", severity="critical"),
        _make_match(pattern_name="github_token", severity="high"),
    ]
    report = build_profile_report(_make_result(matches))
    critical = report.by_severity("critical")
    assert len(critical) == 1
    assert critical[0].pattern_name == "aws_access_key"


def test_profile_report_to_dict_structure():
    match = _make_match()
    report = build_profile_report(_make_result([match]))
    d = report.to_dict()
    assert "aws_access_key" in d
    assert isinstance(d["aws_access_key"], dict)
