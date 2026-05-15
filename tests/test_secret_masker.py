"""Tests for vaultmap.secret_masker and vaultmap.masker_reporter."""
from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

import pytest

from vaultmap.secret_masker import (
    MaskedMatch,
    MaskedResult,
    _mask_full,
    _mask_hash,
    _mask_partial,
    mask_match,
    mask_result,
)
from vaultmap.masker_reporter import print_masked_json_report, print_masked_text_report


def _make_match(value: str = "AKIAIOSFODNN7EXAMPLE", path: str = "app.py", line: int = 10) -> MagicMock:
    m = MagicMock()
    m.value = value
    m.path = path
    m.line = line
    m.pattern = "aws_access_key"
    m.severity = "critical"
    return m


def _make_result(matches=None, files_scanned: int = 3) -> MagicMock:
    r = MagicMock()
    r.matches = matches or []
    r.files_scanned = files_scanned
    return r


# --- masking strategy unit tests ---

class TestMaskFull:
    def test_always_returns_redacted(self):
        assert _mask_full("anything") == "***REDACTED***"

    def test_empty_string(self):
        assert _mask_full("") == "***REDACTED***"


class TestMaskPartial:
    def test_long_value_shows_head_and_tail(self):
        result = _mask_partial("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_short_value_fully_masked(self):
        assert _mask_partial("short") == "***REDACTED***"

    def test_exactly_at_min_len_is_masked(self):
        # 9 chars — below threshold
        assert _mask_partial("123456789") == "***REDACTED***"

    def test_at_threshold_shows_partial(self):
        val = "1234567890"  # exactly 10 chars
        result = _mask_partial(val)
        assert result.startswith("1234")
        assert result.endswith("7890")


class TestMaskHash:
    def test_starts_with_prefix(self):
        assert _mask_hash("secret").startswith("sha256:")

    def test_hash_length(self):
        result = _mask_hash("secret")
        # "sha256:" + 12 hex chars
        assert len(result) == len("sha256:") + 12

    def test_same_input_same_output(self):
        assert _mask_hash("abc") == _mask_hash("abc")

    def test_different_input_different_output(self):
        assert _mask_hash("abc") != _mask_hash("xyz")


# --- mask_match / mask_result ---

def test_mask_match_returns_masked_match():
    m = _make_match()
    mm = mask_match(m, strategy="full")
    assert isinstance(mm, MaskedMatch)
    assert mm.masked_value == "***REDACTED***"
    assert mm.strategy == "full"
    assert mm.original is m


def test_mask_match_partial_default():
    m = _make_match(value="AKIAIOSFODNN7EXAMPLE")
    mm = mask_match(m)  # default strategy
    assert mm.strategy == "partial"
    assert mm.masked_value != m.value


def test_mask_match_to_dict_keys():
    m = _make_match()
    mm = mask_match(m, strategy="hash")
    d = mm.to_dict()
    assert set(d.keys()) == {"path", "line", "pattern", "severity", "masked_value", "strategy"}


def test_mask_result_wraps_all_matches():
    matches = [_make_match(), _make_match(path="other.py", line=20)]
    r = _make_result(matches=matches, files_scanned=5)
    mr = mask_result(r, strategy="full")
    assert isinstance(mr, MaskedResult)
    assert len(mr) == 2
    assert mr.files_scanned == 5


def test_mask_result_no_findings():
    r = _make_result(matches=[], files_scanned=2)
    mr = mask_result(r)
    assert not mr.has_findings()


# --- reporter tests ---

def test_text_report_no_findings():
    mr = MaskedResult(matches=[], files_scanned=1)
    buf = io.StringIO()
    print_masked_text_report(mr, out=buf, color=False)
    assert "No findings" in buf.getvalue()


def test_text_report_shows_path_and_value():
    m = _make_match(path="secret.py", line=42)
    mm = mask_match(m, strategy="partial")
    mr = MaskedResult(matches=[mm], files_scanned=1)
    buf = io.StringIO()
    print_masked_text_report(mr, out=buf, color=False)
    output = buf.getvalue()
    assert "secret.py" in output
    assert "42" in output
    assert "partial" in output


def test_json_report_structure():
    m = _make_match()
    mm = mask_match(m, strategy="hash")
    mr = MaskedResult(matches=[mm], files_scanned=4)
    buf = io.StringIO()
    print_masked_json_report(mr, out=buf)
    data = json.loads(buf.getvalue())
    assert data["files_scanned"] == 4
    assert data["total_findings"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["strategy"] == "hash"


def test_json_report_empty():
    mr = MaskedResult(matches=[], files_scanned=0)
    buf = io.StringIO()
    print_masked_json_report(mr, out=buf)
    data = json.loads(buf.getvalue())
    assert data["total_findings"] == 0
    assert data["findings"] == []
