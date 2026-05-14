"""Tests for vaultmap.secret_annotator."""
from __future__ import annotations

import pytest

from vaultmap.secret_annotator import (
    AnnotatedMatch,
    AnnotatedResult,
    _DEFAULT_HINT,
    _hint_for,
    _references_for,
    annotate_match,
    annotate_result,
)
from vaultmap.scanner import Match, ScanResult


def _make_match(
    pattern_name: str = "generic_secret",
    path: str = "app/config.py",
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


def _make_result(matches=None) -> ScanResult:
    return ScanResult(
        files_scanned=1,
        matches=matches or [],
    )


# --- _hint_for ---

def test_hint_for_aws_access_key():
    hint = _hint_for("aws_access_key")
    assert "IAM" in hint


def test_hint_for_github_token():
    hint = _hint_for("github_token")
    assert "github" in hint.lower()


def test_hint_for_unknown_pattern_returns_default():
    hint = _hint_for("totally_unknown_pattern_xyz")
    assert hint == _DEFAULT_HINT


def test_hint_for_case_insensitive():
    hint = _hint_for("AWS_ACCESS_KEY")
    assert hint != _DEFAULT_HINT


# --- _references_for ---

def test_references_for_aws_returns_url():
    refs = _references_for("aws_access_key")
    assert len(refs) == 1
    assert refs[0].startswith("https://")


def test_references_for_github_returns_url():
    refs = _references_for("github_token")
    assert len(refs) == 1


def test_references_for_unknown_returns_empty():
    refs = _references_for("mystery_pattern")
    assert refs == []


# --- annotate_match ---

def test_annotate_match_returns_annotated_match():
    m = _make_match(pattern_name="aws_access_key")
    ann = annotate_match(m)
    assert isinstance(ann, AnnotatedMatch)
    assert ann.match is m
    assert "IAM" in ann.hint
    assert len(ann.references) == 1


def test_annotate_match_generic_no_references():
    m = _make_match(pattern_name="generic_password")
    ann = annotate_match(m)
    assert ann.references == []
    assert ann.hint != _DEFAULT_HINT


# --- annotate_result ---

def test_annotate_result_empty():
    result = _make_result()
    ar = annotate_result(result)
    assert isinstance(ar, AnnotatedResult)
    assert ar.annotations == []


def test_annotate_result_multiple_matches():
    matches = [
        _make_match(pattern_name="aws_access_key"),
        _make_match(pattern_name="github_token"),
    ]
    result = _make_result(matches)
    ar = annotate_result(result)
    assert len(ar.annotations) == 2
    assert ar.source_result is result


# --- to_dict ---

def test_annotated_match_to_dict_contains_hint():
    m = _make_match(pattern_name="stripe_key")
    ann = annotate_match(m)
    d = ann.to_dict()
    assert "hint" in d
    assert d["pattern"] == "stripe_key"
    assert d["line"] == 10


def test_annotated_match_to_dict_omits_empty_references():
    m = _make_match(pattern_name="generic_secret")
    ann = annotate_match(m)
    d = ann.to_dict()
    assert "references" not in d


def test_annotated_match_to_dict_includes_references_when_present():
    m = _make_match(pattern_name="aws_access_key")
    ann = annotate_match(m)
    d = ann.to_dict()
    assert "references" in d
    assert isinstance(d["references"], list)
