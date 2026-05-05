"""Tests for vaultmap.baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vaultmap.baseline import (
    _fingerprint,
    filter_new_matches,
    is_new,
    load_baseline,
    save_baseline,
)
from vaultmap.scanner import Match


def _make_match(
    file_path: str = "app/config.py",
    line_number: int = 10,
    pattern_id: str = "aws-access-key",
    matched_value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    description: str = "AWS Access Key",
) -> Match:
    return Match(
        file_path=file_path,
        line_number=line_number,
        pattern_id=pattern_id,
        matched_value=matched_value,
        severity=severity,
        description=description,
    )


def test_fingerprint_is_stable():
    m = _make_match()
    assert _fingerprint(m) == _fingerprint(m)


def test_fingerprint_differs_on_line_change():
    m1 = _make_match(line_number=1)
    m2 = _make_match(line_number=2)
    assert _fingerprint(m1) != _fingerprint(m2)


def test_save_and_load_baseline(tmp_path: Path):
    baseline_file = tmp_path / "baseline.json"
    matches = [_make_match(), _make_match(line_number=20, pattern_id="github-token")]
    save_baseline(matches, baseline_file)

    data = json.loads(baseline_file.read_text())
    assert data["version"] == 1
    assert len(data["fingerprints"]) == 2

    loaded = load_baseline(baseline_file)
    assert isinstance(loaded, set)
    assert len(loaded) == 2


def test_load_baseline_missing_file_returns_empty_set(tmp_path: Path):
    result = load_baseline(tmp_path / "nonexistent.json")
    assert result == set()


def test_filter_new_matches_excludes_baseline():
    m1 = _make_match(line_number=1)
    m2 = _make_match(line_number=2)
    baseline = {_fingerprint(m1)}
    new_matches = filter_new_matches([m1, m2], baseline)
    assert new_matches == [m2]


def test_filter_new_matches_all_new():
    matches = [_make_match(line_number=i) for i in range(3)]
    new_matches = filter_new_matches(matches, set())
    assert len(new_matches) == 3


def test_is_new_true_when_not_in_baseline():
    m = _make_match()
    assert is_new(m, set()) is True


def test_is_new_false_when_in_baseline():
    m = _make_match()
    baseline = {_fingerprint(m)}
    assert is_new(m, baseline) is False


def test_save_baseline_deduplicates(tmp_path: Path):
    m = _make_match()
    save_baseline([m, m, m], tmp_path / "baseline.json")
    data = json.loads((tmp_path / "baseline.json").read_text())
    assert len(data["fingerprints"]) == 1
