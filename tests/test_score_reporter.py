"""Tests for vaultmap.score_reporter."""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

from vaultmap.secret_scorer import ScoredMatch, ScoredResult
from vaultmap.score_reporter import print_score_text_report, print_score_json_report, _label, _bar


def _make_scored(score: int, path="src/app.py", line=1, pattern="aws_key") -> ScoredMatch:
    m = MagicMock()
    m.path = path
    m.line_number = line
    m.pattern_name = pattern
    breakdown = {"severity": score, "entropy": 0, "validation": 0, "path": 0}
    return ScoredMatch(match=m, score=score, breakdown=breakdown)


def _make_result(items) -> ScoredResult:
    sr = MagicMock(spec=ScoredResult)
    sr.scored = items
    sr.top = lambda n=10: sorted(items, key=lambda x: x.score, reverse=True)[:n]
    return sr


class TestLabel:
    def test_critical_threshold(self):
        assert _label(75) == "CRITICAL"
        assert _label(100) == "CRITICAL"

    def test_high_threshold(self):
        assert _label(50) == "HIGH"
        assert _label(74) == "HIGH"

    def test_medium_threshold(self):
        assert _label(25) == "MEDIUM"

    def test_low_threshold(self):
        assert _label(0) == "LOW"
        assert _label(24) == "LOW"


class TestBar:
    def test_full_bar(self):
        assert _bar(100).count("#") == 20

    def test_empty_bar(self):
        assert _bar(0).count("#") == 0

    def test_bar_total_width(self):
        b = _bar(50)
        assert len(b) == 22  # 20 + brackets


class TestTextReport:
    def test_no_findings_message(self):
        sr = _make_result([])
        out = io.StringIO()
        print_score_text_report(sr, out=out)
        assert "No scored findings" in out.getvalue()

    def test_shows_score(self):
        sr = _make_result([_make_scored(80)])
        out = io.StringIO()
        print_score_text_report(sr, out=out)
        assert "80" in out.getvalue()

    def test_shows_pattern_name(self):
        sr = _make_result([_make_scored(40, pattern="github_token")])
        out = io.StringIO()
        print_score_text_report(sr, out=out)
        assert "github_token" in out.getvalue()

    def test_top_n_respected(self):
        items = [_make_scored(i * 5, line=i) for i in range(1, 11)]
        sr = _make_result(items)
        out = io.StringIO()
        print_score_text_report(sr, out=out, top=3)
        # 3 entries means 3 numbered lines starting with index
        text = out.getvalue()
        assert "  1." in text
        assert "  4." not in text


class TestJsonReport:
    def test_json_structure(self):
        sr = _make_result([_make_scored(60)])
        out = io.StringIO()
        print_score_json_report(sr, out=out)
        data = json.loads(out.getvalue())
        assert "scored_findings" in data
        assert "total" in data

    def test_json_total_count(self):
        items = [_make_scored(i * 10) for i in range(5)]
        sr = _make_result(items)
        out = io.StringIO()
        print_score_json_report(sr, out=out)
        data = json.loads(out.getvalue())
        assert data["total"] == 5
