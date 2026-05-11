"""Tests for vaultmap.redactor."""

from __future__ import annotations

import pytest

from vaultmap.redactor import redact_value, redact_line, redact_match, redact_result
from vaultmap.scanner import Match, ScanResult


def _make_match(
    value: str = "AKIAIOSFODNN7EXAMPLE",
    line_content: str = "aws_key = AKIAIOSFODNN7EXAMPLE",
    path: str = "config.py",
    line_number: int = 5,
    pattern_name: str = "aws_access_key",
    severity: str = "critical",
) -> Match:
    return Match(
        path=path,
        line_number=line_number,
        pattern_name=pattern_name,
        severity=severity,
        value=value,
        line_content=line_content,
    )


# ---------------------------------------------------------------------------
# redact_value
# ---------------------------------------------------------------------------

def test_redact_value_keeps_prefix_and_suffix():
    result = redact_value("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")
    assert result.endswith("MPLE")


def test_redact_value_middle_is_masked():
    result = redact_value("AKIAIOSFODNN7EXAMPLE")
    middle = result[4:-4]
    assert set(middle) == {"*"}


def test_redact_value_short_string_fully_masked():
    result = redact_value("abc")
    assert "*" in result
    assert "a" not in result


def test_redact_value_minimum_mask_length():
    result = redact_value("ab")
    assert len(result) >= 8


# ---------------------------------------------------------------------------
# redact_line
# ---------------------------------------------------------------------------

def test_redact_line_replaces_value():
    line = "secret = AKIAIOSFODNN7EXAMPLE"
    result = redact_line(line, "AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "AKIA" in result


def test_redact_line_empty_value_unchanged():
    line = "nothing here"
    assert redact_line(line, "") == line


# ---------------------------------------------------------------------------
# redact_match
# ---------------------------------------------------------------------------

def test_redact_match_value_is_masked():
    m = _make_match()
    redacted = redact_match(m)
    assert redacted.value != m.value
    assert "*" in redacted.value


def test_redact_match_line_content_is_masked():
    m = _make_match()
    redacted = redact_match(m)
    assert m.value not in redacted.line_content


def test_redact_match_metadata_preserved():
    m = _make_match()
    redacted = redact_match(m)
    assert redacted.path == m.path
    assert redacted.line_number == m.line_number
    assert redacted.pattern_name == m.pattern_name
    assert redacted.severity == m.severity


# ---------------------------------------------------------------------------
# redact_result
# ---------------------------------------------------------------------------

def test_redact_result_all_matches_masked():
    matches = [_make_match(), _make_match(path="other.py", line_number=10)]
    result = ScanResult(files_scanned=2, matches=matches)
    redacted = redact_result(result)
    for m in redacted.matches:
        assert "*" in m.value


def test_redact_result_files_scanned_unchanged():
    result = ScanResult(files_scanned=7, matches=[])
    assert redact_result(result).files_scanned == 7
