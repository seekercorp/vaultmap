"""Tests for vaultmap.secret_validator."""
from __future__ import annotations

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.secret_validator import (
    ValidatedMatch,
    plausible_only,
    validate_match,
    validate_result,
)


def _make_match(value: str, pattern: str = "generic", path: str = "app.py", line: int = 1) -> Match:
    return Match(path=path, line_number=line, pattern_name=pattern, value=value, severity="high")


# ---------------------------------------------------------------------------
# validate_match — plausible cases
# ---------------------------------------------------------------------------

def test_real_looking_aws_key_is_plausible():
    m = _make_match("AKIAIOSFODNN7EXAMPLE", pattern="aws_access_key")
    # Override value to remove 'example' fragment for this test
    m = _make_match("AKIAIOSFODNN7Z3XQPRT", pattern="aws_access_key")
    result = validate_match(m)
    assert result.is_plausible is True
    assert result.reason == "passed heuristic checks"


def test_long_random_value_is_plausible():
    m = _make_match("ghp_Abc123XYZdef456uvw789", pattern="github_token")
    result = validate_match(m)
    assert result.is_plausible is True


# ---------------------------------------------------------------------------
# validate_match — implausible cases
# ---------------------------------------------------------------------------

def test_short_value_is_not_plausible():
    m = _make_match("abc", pattern="generic")
    result = validate_match(m)
    assert result.is_plausible is False
    assert "too short" in result.reason


def test_placeholder_fragment_detected():
    m = _make_match("your_secret_key_here", pattern="generic")
    result = validate_match(m)
    assert result.is_plausible is False
    assert "placeholder fragment" in result.reason


def test_example_fragment_detected():
    m = _make_match("AKIAIOSFODNN7EXAMPLE", pattern="aws_access_key")
    result = validate_match(m)
    assert result.is_plausible is False


def test_uniform_repetition_is_not_plausible():
    m = _make_match("aaaaaaaaaaaaa", pattern="generic")
    result = validate_match(m)
    assert result.is_plausible is False
    assert "uniform" in result.reason


def test_changeme_is_not_plausible():
    m = _make_match("changeme_password", pattern="generic")
    result = validate_match(m)
    assert result.is_plausible is False


# ---------------------------------------------------------------------------
# validate_result
# ---------------------------------------------------------------------------

def test_validate_result_returns_one_per_match():
    matches = [
        _make_match("AKIAIOSFODNN7Z3XQPRT"),
        _make_match("example_key_here"),
    ]
    result = ScanResult(path="app.py", matches=matches, files_scanned=1)
    validated = validate_result(result)
    assert len(validated) == 2
    assert isinstance(validated[0], ValidatedMatch)


# ---------------------------------------------------------------------------
# plausible_only
# ---------------------------------------------------------------------------

def test_plausible_only_filters_correctly():
    matches = [
        _make_match("AKIAIOSFODNN7Z3XQPRT"),
        _make_match("example_key_here"),
        _make_match("ghp_Abc123XYZdef456uvw789"),
    ]
    result = ScanResult(path="app.py", matches=matches, files_scanned=1)
    validated = validate_result(result)
    plausible = plausible_only(validated)
    assert len(plausible) == 2
    assert all(v.is_plausible for v in plausible)


def test_plausible_only_empty_when_all_fake():
    matches = [_make_match("test_key_dummy"), _make_match("xxx")]
    result = ScanResult(path="app.py", matches=matches, files_scanned=1)
    plausible = plausible_only(validate_result(result))
    assert plausible == []
