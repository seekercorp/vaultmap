"""Tests for vaultmap.secret_fingerprinter."""

from __future__ import annotations

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.secret_fingerprinter import (
    FingerprintedMatch,
    FingerprintedResult,
    fingerprint_match,
    fingerprint_result,
    unique_fingerprints,
    _stable_fingerprint,
)


def _make_match(
    path: str = "src/config.py",
    line: int = 10,
    pattern_name: str = "aws_access_key",
    severity: str = "critical",
    value: str = "AKIAIOSFODNN7EXAMPLE",
) -> Match:
    return Match(
        path=path,
        line=line,
        pattern_name=pattern_name,
        severity=severity,
        value=value,
    )


def _make_result(matches=None) -> ScanResult:
    return ScanResult(
        files_scanned=1,
        matches=matches or [],
    )


# ---------------------------------------------------------------------------
# _stable_fingerprint
# ---------------------------------------------------------------------------

def test_fingerprint_is_stable_across_calls():
    m = _make_match()
    assert _stable_fingerprint(m) == _stable_fingerprint(m)


def test_fingerprint_differs_on_different_line():
    m1 = _make_match(line=1)
    m2 = _make_match(line=2)
    assert _stable_fingerprint(m1) != _stable_fingerprint(m2)


def test_fingerprint_differs_on_different_path():
    m1 = _make_match(path="a.py")
    m2 = _make_match(path="b.py")
    assert _stable_fingerprint(m1) != _stable_fingerprint(m2)


def test_fingerprint_normalises_whitespace_in_value():
    m1 = _make_match(value="  AKIAIOSFODNN7EXAMPLE  ")
    m2 = _make_match(value="AKIAIOSFODNN7EXAMPLE")
    assert _stable_fingerprint(m1) == _stable_fingerprint(m2)


def test_fingerprint_is_64_hex_chars():
    fp = _stable_fingerprint(_make_match())
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# fingerprint_match
# ---------------------------------------------------------------------------

def test_fingerprint_match_returns_fingerprinted_match():
    m = _make_match()
    fm = fingerprint_match(m)
    assert isinstance(fm, FingerprintedMatch)
    assert fm.match is m


def test_short_id_is_first_8_chars():
    m = _make_match()
    fm = fingerprint_match(m)
    assert fm.short_id == fm.fingerprint[:8]
    assert len(fm.short_id) == 8


def test_to_dict_contains_required_keys():
    fm = fingerprint_match(_make_match())
    d = fm.to_dict()
    for key in ("fingerprint", "short_id", "path", "line", "pattern", "severity", "value"):
        assert key in d


# ---------------------------------------------------------------------------
# fingerprint_result
# ---------------------------------------------------------------------------

def test_fingerprint_result_wraps_all_matches():
    matches = [_make_match(line=i) for i in range(1, 4)]
    result = _make_result(matches)
    fr = fingerprint_result(result)
    assert isinstance(fr, FingerprintedResult)
    assert len(fr.matches) == 3


def test_fingerprint_result_empty_result():
    fr = fingerprint_result(_make_result())
    assert fr.matches == []


def test_by_short_id_finds_match():
    matches = [_make_match(line=i) for i in range(1, 3)]
    fr = fingerprint_result(_make_result(matches))
    target = fr.matches[0]
    found = fr.by_short_id(target.short_id)
    assert found is target


def test_by_short_id_returns_none_for_unknown():
    fr = fingerprint_result(_make_result([_make_match()]))
    assert fr.by_short_id("00000000") is None


# ---------------------------------------------------------------------------
# unique_fingerprints
# ---------------------------------------------------------------------------

def test_unique_fingerprints_deduplicates():
    m = _make_match()
    fm1 = fingerprint_match(m)
    fm2 = fingerprint_match(m)  # same underlying match
    result = unique_fingerprints([fm1, fm2])
    assert len(result) == 1


def test_unique_fingerprints_sorted():
    matches = [_make_match(line=i) for i in range(5, 0, -1)]
    fms = [fingerprint_match(m) for m in matches]
    fps = unique_fingerprints(fms)
    assert fps == sorted(fps)
