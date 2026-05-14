"""Tests for vaultmap.secret_normalizer."""

from __future__ import annotations

import pytest

from vaultmap.secret_normalizer import (
    NormalizedMatch,
    NormalizedResult,
    normalize_match,
    normalize_result,
    normalize_value,
)
from vaultmap.scanner import Match, ScanResult


def _make_match(value: str, path: str = "app.py", line: int = 1) -> Match:
    return Match(
        path=path,
        line=line,
        pattern_name="aws_access_key",
        severity="high",
        value=value,
        matched_text=value,
    )


def _make_result(matches) -> ScanResult:
    return ScanResult(matches=list(matches), scanned_files=3)


# --- normalize_value ---

def test_normalize_value_plain_string_unchanged():
    val, transforms = normalize_value("AKIAIOSFODNN7EXAMPLE")
    assert val == "AKIAIOSFODNN7EXAMPLE"
    assert transforms == []


def test_normalize_value_strips_double_quotes():
    val, transforms = normalize_value('"AKIAIOSFODNN7EXAMPLE"')
    assert val == "AKIAIOSFODNN7EXAMPLE"
    assert "strip_quotes" in transforms


def test_normalize_value_strips_single_quotes():
    val, transforms = normalize_value("'mysecrettoken'")
    assert val == "mysecrettoken"
    assert "strip_quotes" in transforms


def test_normalize_value_strips_assignment_prefix_equals():
    val, transforms = normalize_value("SECRET_KEY = abc123")
    assert val == "abc123"
    assert "strip_assignment" in transforms


def test_normalize_value_strips_assignment_prefix_colon():
    val, transforms = normalize_value("password: hunter2")
    assert val == "hunter2"
    assert "strip_assignment" in transforms


def test_normalize_value_collapses_whitespace():
    val, transforms = normalize_value("a b c d")
    assert val == "abcd"
    assert "collapse_whitespace" in transforms


def test_normalize_value_multiple_transforms():
    val, transforms = normalize_value('KEY = "my secret"')
    assert "strip_assignment" in transforms
    assert "strip_quotes" in transforms
    assert "collapse_whitespace" in transforms
    assert val == "mysecret"


# --- normalize_match ---

def test_normalize_match_returns_normalized_match_type():
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    result = normalize_match(m)
    assert isinstance(result, NormalizedMatch)


def test_normalize_match_preserves_original():
    m = _make_match('"AKIAIOSFODNN7EXAMPLE"')
    nm = normalize_match(m)
    assert nm.original is m
    assert nm.original.value == '"AKIAIOSFODNN7EXAMPLE"'


def test_normalize_match_normalized_value_stripped():
    m = _make_match('"AKIAIOSFODNN7EXAMPLE"')
    nm = normalize_match(m)
    assert nm.normalized_value == "AKIAIOSFODNN7EXAMPLE"


def test_normalize_match_to_dict_has_expected_keys():
    m = _make_match("token123", path="config.py", line=42)
    nm = normalize_match(m)
    d = nm.to_dict()
    assert d["path"] == "config.py"
    assert d["line"] == 42
    assert d["original_value"] == "token123"
    assert "normalized_value" in d
    assert "transformations" in d


# --- normalize_result ---

def test_normalize_result_returns_normalized_result_type():
    result = _make_result([_make_match("abc")])
    nr = normalize_result(result)
    assert isinstance(nr, NormalizedResult)


def test_normalize_result_preserves_scanned_files():
    result = _make_result([])
    nr = normalize_result(result)
    assert nr.scanned_files == 3


def test_normalize_result_normalizes_all_matches():
    matches = [_make_match('"tok1"'), _make_match('"tok2"')]
    result = _make_result(matches)
    nr = normalize_result(result)
    assert len(nr.matches) == 2
    assert all(isinstance(m, NormalizedMatch) for m in nr.matches)


def test_normalize_result_empty_matches():
    result = _make_result([])
    nr = normalize_result(result)
    assert nr.matches == []
