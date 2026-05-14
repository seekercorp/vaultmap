"""Tests for vaultmap.secret_scorer."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from vaultmap.secret_scorer import (
    ScoredMatch,
    ScoredResult,
    _score_match,
    score_result,
    _ENTROPY_BONUS,
    _VALIDATION_BONUS,
    _PATH_BONUS,
)


def _make_match(path="src/app.py", line=10, pattern="generic", severity="high"):
    m = MagicMock()
    m.path = path
    m.line_number = line
    m.pattern_name = pattern
    m.severity = severity
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


class TestScoreMatch:
    def test_severity_contributes(self):
        m = _make_match(severity="critical")
        sm = _score_match(m)
        assert sm.breakdown["severity"] == 40

    def test_entropy_bonus_applied_above_threshold(self):
        m = _make_match()
        sm = _score_match(m, entropy=4.5)
        assert sm.breakdown["entropy"] == _ENTROPY_BONUS

    def test_entropy_bonus_not_applied_below_threshold(self):
        m = _make_match()
        sm = _score_match(m, entropy=2.0)
        assert sm.breakdown["entropy"] == 0

    def test_validation_bonus_applied_when_plausible(self):
        m = _make_match()
        sm = _score_match(m, plausible=True)
        assert sm.breakdown["validation"] == _VALIDATION_BONUS

    def test_path_bonus_applied_for_sensitive_path(self):
        m = _make_match(path=".env")
        sm = _score_match(m)
        assert sm.breakdown["path"] == _PATH_BONUS

    def test_path_bonus_not_applied_for_regular_path(self):
        m = _make_match(path="src/utils.py")
        sm = _score_match(m)
        assert sm.breakdown["path"] == 0

    def test_score_capped_at_100(self):
        m = _make_match(severity="critical", path=".env")
        sm = _score_match(m, entropy=5.0, plausible=True)
        assert sm.score <= 100

    def test_to_dict_contains_required_keys(self):
        m = _make_match()
        sm = _score_match(m)
        d = sm.to_dict()
        assert {"path", "line", "pattern", "score", "breakdown"} <= d.keys()


class TestScoredResult:
    def test_top_returns_sorted_descending(self):
        matches = [_make_match(line=i, severity="low") for i in range(5)]
        result = _make_result(matches)
        sr = score_result(result)
        scores = [s.score for s in sr.top(5)]
        assert scores == sorted(scores, reverse=True)

    def test_above_threshold_filters(self):
        matches = [
            _make_match(line=1, severity="critical"),
            _make_match(line=2, severity="low"),
        ]
        result = _make_result(matches)
        sr = score_result(result)
        high = sr.above(35)
        assert all(s.score >= 35 for s in high)

    def test_entropy_map_used(self):
        m = _make_match(path="a.py", line=1)
        result = _make_result([m])
        sr = score_result(result, entropy_map={("a.py", 1): 5.0})
        assert sr.scored[0].breakdown["entropy"] == _ENTROPY_BONUS

    def test_plausible_set_used(self):
        m = _make_match(path="a.py", line=1)
        result = _make_result([m])
        sr = score_result(result, plausible_set={("a.py", 1)})
        assert sr.scored[0].breakdown["validation"] == _VALIDATION_BONUS
