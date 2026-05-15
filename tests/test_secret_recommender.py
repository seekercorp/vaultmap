"""Tests for vaultmap.secret_recommender."""
from __future__ import annotations

import pytest

from vaultmap.secret_recommender import (
    RecommendationReport,
    RecommendedMatch,
    _recommendations_for,
    build_recommendation_report,
    recommend_match,
)
from vaultmap.scanner import Match, ScanResult


def _make_match(
    pattern_name: str = "generic_password",
    path: str = "config.py",
    line: int = 10,
    severity: str = "high",
    value: str = "s3cr3t",
) -> Match:
    return Match(
        path=path,
        line=line,
        pattern_name=pattern_name,
        severity=severity,
        value=value,
    )


def _make_result(*matches: Match) -> ScanResult:
    return ScanResult(
        files_scanned=1,
        matches=list(matches),
    )


# --- _recommendations_for ---

def test_recommendations_for_aws_key():
    recs = _recommendations_for("aws_access_key")
    assert any("IAM" in r for r in recs)


def test_recommendations_for_github_token():
    recs = _recommendations_for("github_token")
    assert any("github.com" in r.lower() for r in recs)


def test_recommendations_for_private_key():
    recs = _recommendations_for("private_key_header")
    assert any("private key" in r.lower() for r in recs)


def test_recommendations_for_unknown_falls_back_to_default():
    recs = _recommendations_for("totally_unknown_pattern")
    assert len(recs) >= 1
    assert any("secrets manager" in r.lower() for r in recs)


# --- recommend_match ---

def test_recommend_match_returns_recommended_match():
    m = _make_match(pattern_name="aws_access_key")
    rm = recommend_match(m)
    assert isinstance(rm, RecommendedMatch)
    assert rm.match is m
    assert len(rm.recommendations) > 0


def test_recommend_match_to_dict_keys():
    m = _make_match()
    rm = recommend_match(m)
    d = rm.to_dict()
    assert set(d.keys()) == {"path", "line", "pattern", "severity", "recommendations"}


def test_recommend_match_to_dict_values():
    m = _make_match(pattern_name="github_token", path="app.py", line=42, severity="critical")
    rm = recommend_match(m)
    d = rm.to_dict()
    assert d["path"] == "app.py"
    assert d["line"] == 42
    assert d["pattern"] == "github_token"
    assert d["severity"] == "critical"
    assert isinstance(d["recommendations"], list)


# --- build_recommendation_report ---

def test_build_report_empty_result():
    result = _make_result()
    report = build_recommendation_report(result)
    assert isinstance(report, RecommendationReport)
    assert len(report) == 0


def test_build_report_single_match():
    m = _make_match(pattern_name="aws_access_key")
    result = _make_result(m)
    report = build_recommendation_report(result)
    assert len(report) == 1
    assert report.items[0].match is m


def test_build_report_multiple_matches():
    m1 = _make_match(pattern_name="aws_access_key")
    m2 = _make_match(pattern_name="github_token", line=20)
    result = _make_result(m1, m2)
    report = build_recommendation_report(result)
    assert len(report) == 2


def test_for_pattern_filters_correctly():
    m1 = _make_match(pattern_name="aws_access_key")
    m2 = _make_match(pattern_name="github_token", line=20)
    result = _make_result(m1, m2)
    report = build_recommendation_report(result)
    aws_items = report.for_pattern("aws_access_key")
    assert len(aws_items) == 1
    assert aws_items[0].match.pattern_name == "aws_access_key"


def test_for_pattern_no_match_returns_empty():
    m = _make_match(pattern_name="aws_access_key")
    result = _make_result(m)
    report = build_recommendation_report(result)
    assert report.for_pattern("nonexistent") == []
