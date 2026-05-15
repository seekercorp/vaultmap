"""Tests for vaultmap.secret_inhibitor."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultmap.secret_inhibitor import (
    DEFAULT_INHIBITORS,
    InhibitedMatch,
    InhibitedResult,
    _is_inhibited,
    inhibit_match,
    inhibit_result,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(value: str = "AKIAIOSFODNN7EXAMPLE", pattern: str = "aws_access_key") -> MagicMock:
    m = MagicMock()
    m.value = value
    m.pattern_name = pattern
    m.path = "src/config.py"
    m.line = 10
    return m


def _make_result(matches) -> MagicMock:
    r = MagicMock()
    r.matches = matches
    return r


# ---------------------------------------------------------------------------
# _is_inhibited
# ---------------------------------------------------------------------------

class TestIsInhibited:
    def test_plain_example_fragment(self):
        hit, reason = _is_inhibited("AKIAIOSFODNN7example", DEFAULT_INHIBITORS)
        assert hit is True
        assert reason == "example"

    def test_placeholder_fragment(self):
        hit, _ = _is_inhibited("my_placeholder_token", DEFAULT_INHIBITORS)
        assert hit is True

    def test_real_looking_value_not_inhibited(self):
        hit, reason = _is_inhibited("AKIAIOSFODNN7REALKEY", DEFAULT_INHIBITORS)
        assert hit is False
        assert reason == ""

    def test_case_insensitive_match(self):
        hit, _ = _is_inhibited("CHANGEME_NOW", DEFAULT_INHIBITORS)
        assert hit is True

    def test_glob_pattern_xxxx(self):
        hit, _ = _is_inhibited("xxxxsomesecretvalue", DEFAULT_INHIBITORS)
        assert hit is True

    def test_extra_pattern_honoured(self):
        hit, reason = _is_inhibited("mysupersecret_NOTEST", ["notest"])
        assert hit is True
        assert reason == "notest"


# ---------------------------------------------------------------------------
# inhibit_match
# ---------------------------------------------------------------------------

def test_inhibit_match_flags_example_value():
    m = _make_match(value="AKIAIOSFODNN7EXAMPLE")
    result = inhibit_match(m)
    assert isinstance(result, InhibitedMatch)
    assert result.inhibited is True
    assert result.reason != ""


def test_inhibit_match_clean_value_not_inhibited():
    m = _make_match(value="AKIAIOSFODNN7REALKEY")
    result = inhibit_match(m)
    assert result.inhibited is False


def test_inhibit_match_extra_pattern_applied():
    m = _make_match(value="token_INTERNAL_ONLY")
    result = inhibit_match(m, extra_patterns=["internal_only"])
    assert result.inhibited is True


def test_inhibited_match_to_dict_keys():
    m = _make_match()
    d = inhibit_match(m).to_dict()
    assert {"inhibited", "reason", "path", "line", "pattern", "value"} <= d.keys()


# ---------------------------------------------------------------------------
# inhibit_result
# ---------------------------------------------------------------------------

def test_inhibit_result_active_and_suppressed_split():
    matches = [
        _make_match(value="AKIAIOSFODNN7EXAMPLE"),   # inhibited
        _make_match(value="AKIAIOSFODNN7REALKEY"),    # active
        _make_match(value="dummy_token_here"),         # inhibited
    ]
    res = inhibit_result(_make_result(matches))
    assert isinstance(res, InhibitedResult)
    assert len(res.active) == 1
    assert len(res.suppressed) == 2


def test_inhibit_result_empty_matches():
    res = inhibit_result(_make_result([]))
    assert res.active == []
    assert res.suppressed == []


def test_inhibit_result_preserves_source():
    src = _make_result([])
    res = inhibit_result(src)
    assert res.source is src
