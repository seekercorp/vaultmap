"""Tests for vaultmap.deduplicator."""

from __future__ import annotations

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.deduplicator import (
    deduplicate_matches,
    deduplicate_result,
    duplicate_summary,
)


def _match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    path: str = "config.py",
    line: int = 10,
    severity: str = "high",
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        path=path,
        line=line,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# deduplicate_matches
# ---------------------------------------------------------------------------

def test_no_duplicates_unchanged():
    m1 = _match(line=1)
    m2 = _match(pattern_name="github_token", value="ghp_abc", line=2)
    result = deduplicate_matches([m1, m2])
    assert len(result) == 2


def test_exact_duplicate_kept_once():
    m1 = _match(line=5)
    m2 = _match(line=5)  # identical
    result = deduplicate_matches([m1, m2])
    assert len(result) == 1


def test_same_value_different_lines_keeps_first_occurrence():
    m1 = _match(line=20)
    m2 = _match(line=5)   # same key, earlier line
    result = deduplicate_matches([m1, m2])
    assert len(result) == 1
    assert result[0].line == 5


def test_different_paths_not_deduplicated():
    m1 = _match(path="a.py", line=1)
    m2 = _match(path="b.py", line=1)
    result = deduplicate_matches([m1, m2])
    assert len(result) == 2


def test_empty_input_returns_empty():
    assert deduplicate_matches([]) == []


# ---------------------------------------------------------------------------
# deduplicate_result
# ---------------------------------------------------------------------------

def test_deduplicate_result_preserves_metadata():
    m1 = _match(line=1)
    m2 = _match(line=2)  # duplicate of m1
    sr = ScanResult(matches=[m1, m2], files_scanned=7, errors=["oops"])
    deduped = deduplicate_result(sr)
    assert deduped.files_scanned == 7
    assert deduped.errors == ["oops"]
    assert len(deduped.matches) == 1


# ---------------------------------------------------------------------------
# duplicate_summary
# ---------------------------------------------------------------------------

def test_duplicate_summary_counts_correctly():
    m1 = _match(line=1)
    m2 = _match(line=2)
    m3 = _match(pattern_name="github_token", value="ghp_abc", line=3)
    summary = duplicate_summary([m1, m2, m3])
    key_aws = ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "config.py")
    key_gh = ("github_token", "ghp_abc", "config.py")
    assert summary[key_aws] == 2
    assert summary[key_gh] == 1
