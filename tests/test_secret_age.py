"""Tests for vaultmap.secret_age."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from vaultmap.scanner import Match, ScanResult
from vaultmap.secret_age import (
    AgedMatch,
    AgeReport,
    _load_age_db,
    _save_age_db,
    update_and_build_report,
)


def _make_match(path: str = "app/config.py", line: int = 10, value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(
        path=path,
        line_number=line,
        pattern_name="aws_access_key",
        severity="high",
        matched_value=value,
        line_content=f'aws_key = "{value}"',
    )


def _make_result(*matches: Match) -> ScanResult:
    return ScanResult(path="app/", matches=list(matches), files_scanned=1)


# ---------------------------------------------------------------------------
# AgedMatch helpers
# ---------------------------------------------------------------------------

def test_aged_match_not_stale_when_recent():
    m = AgedMatch(match=_make_match(), first_seen=time.time(), age_days=5.0)
    assert not m.is_stale(threshold_days=30)


def test_aged_match_stale_when_old():
    m = AgedMatch(match=_make_match(), first_seen=time.time() - 40 * 86400, age_days=40.0)
    assert m.is_stale(threshold_days=30)


# ---------------------------------------------------------------------------
# AgeReport helpers
# ---------------------------------------------------------------------------

def test_age_report_stale_filters_correctly():
    recent = AgedMatch(match=_make_match(), first_seen=time.time(), age_days=2.0)
    old = AgedMatch(match=_make_match(line=20), first_seen=time.time() - 50 * 86400, age_days=50.0)
    report = AgeReport(aged=[recent, old])
    assert report.stale == [old]


def test_age_report_oldest_returns_max():
    a = AgedMatch(match=_make_match(), first_seen=0.0, age_days=10.0)
    b = AgedMatch(match=_make_match(line=5), first_seen=0.0, age_days=99.0)
    report = AgeReport(aged=[a, b])
    assert report.oldest() is b


def test_age_report_oldest_empty_returns_none():
    assert AgeReport().oldest() is None


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def test_load_age_db_missing_file_returns_empty(tmp_path):
    assert _load_age_db(tmp_path / "nonexistent.json") == {}


def test_save_and_load_roundtrip(tmp_path):
    db = {"fp1": 1_700_000_000.0, "fp2": 1_710_000_000.0}
    p = tmp_path / "age.json"
    _save_age_db(db, p)
    assert _load_age_db(p) == db


# ---------------------------------------------------------------------------
# update_and_build_report
# ---------------------------------------------------------------------------

def test_new_fingerprint_recorded(tmp_path):
    age_file = tmp_path / "age.json"
    match = _make_match()
    result = _make_result(match)
    now = 1_720_000_000.0
    report = update_and_build_report(result, age_file=age_file, now=now)
    assert len(report.aged) == 1
    assert report.aged[0].age_days == pytest.approx(0.0, abs=1e-6)


def test_existing_fingerprint_preserves_first_seen(tmp_path):
    age_file = tmp_path / "age.json"
    match = _make_match()
    result = _make_result(match)
    first_now = 1_700_000_000.0
    update_and_build_report(result, age_file=age_file, now=first_now)

    later_now = first_now + 10 * 86_400  # 10 days later
    report = update_and_build_report(result, age_file=age_file, now=later_now)
    assert report.aged[0].age_days == pytest.approx(10.0, abs=1e-6)


def test_stale_detection_end_to_end(tmp_path):
    age_file = tmp_path / "age.json"
    match = _make_match()
    result = _make_result(match)
    first_now = 1_700_000_000.0
    update_and_build_report(result, age_file=age_file, now=first_now)

    later_now = first_now + 35 * 86_400
    report = update_and_build_report(result, age_file=age_file, now=later_now)
    assert len(report.stale) == 1
