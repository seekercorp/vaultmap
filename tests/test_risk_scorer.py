"""Tests for vaultmap.risk_scorer."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultmap.risk_scorer import (
    MatchRisk,
    RiskReport,
    _path_multiplier,
    _risk_level,
    score_match,
    score_result,
)


def _make_match(severity="high", path="src/app.py", from_entropy=False):
    m = MagicMock()
    m.severity = severity
    m.path = path
    m.from_entropy = from_entropy
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


# --- _path_multiplier ---

def test_path_multiplier_neutral_file():
    assert _path_multiplier("src/utils.py") == 1.0


def test_path_multiplier_env_file():
    assert _path_multiplier(".env") == 1.5


def test_path_multiplier_config_file():
    assert _path_multiplier("app_config.yaml") == 1.5


def test_path_multiplier_case_insensitive():
    assert _path_multiplier("SECRET_KEYS.py") == 1.5


# --- _risk_level ---

@pytest.mark.parametrize("score,expected", [
    (0, "info"),
    (10, "low"),
    (30, "medium"),
    (75, "high"),
    (150, "critical"),
    (9.9, "info"),
    (74.9, "medium"),
])
def test_risk_level_thresholds(score, expected):
    assert _risk_level(score) == expected


# --- score_match ---

def test_score_match_high_severity_neutral_path():
    m = _make_match(severity="high", path="main.py")
    mr = score_match(m)
    assert isinstance(mr, MatchRisk)
    assert mr.base_score == 25
    assert mr.path_multiplier == 1.0
    assert mr.entropy_bonus == 0
    assert mr.total == 25.0


def test_score_match_critical_sensitive_path():
    m = _make_match(severity="critical", path=".env")
    mr = score_match(m)
    assert mr.base_score == 40
    assert mr.path_multiplier == 1.5
    assert mr.total == 60.0


def test_score_match_entropy_bonus_applied():
    m = _make_match(severity="medium", path="app.py", from_entropy=True)
    mr = score_match(m)
    assert mr.entropy_bonus == 8
    assert mr.total == (12 + 8) * 1.0


def test_score_match_unknown_severity_defaults_to_low():
    m = _make_match(severity="unknown", path="app.py")
    mr = score_match(m)
    assert mr.base_score == 5


# --- score_result ---

def test_score_result_empty_matches():
    result = _make_result([])
    report = score_result(result)
    assert report.total_score == 0.0
    assert report.risk_level == "info"
    assert report.is_high_risk is False


def test_score_result_aggregates_matches():
    matches = [
        _make_match(severity="critical", path=".env"),
        _make_match(severity="high", path="main.py"),
        _make_match(severity="medium", path="config.py"),
    ]
    result = _make_result(matches)
    report = score_result(result)
    assert report.total_score > 0
    assert isinstance(report, RiskReport)
    assert len(report.match_risks) == 3


def test_score_result_is_high_risk_for_many_criticals():
    matches = [_make_match(severity="critical", path=".env") for _ in range(5)]
    result = _make_result(matches)
    report = score_result(result)
    assert report.is_high_risk is True
