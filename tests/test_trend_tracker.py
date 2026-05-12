"""Tests for vaultmap.trend_tracker."""
import json
from pathlib import Path

import pytest

from vaultmap.trend_tracker import (
    TrendEntry,
    TrendReport,
    _load_entries,
    load_trend_report,
    record_entry,
)


@pytest.fixture()
def trend_file(tmp_path: Path) -> Path:
    return tmp_path / ".vaultmap" / "trends.json"


def test_record_entry_creates_file(trend_file: Path) -> None:
    record_entry(5, {"high": 2, "medium": 3}, 10, trend_file=trend_file)
    assert trend_file.exists()


def test_record_entry_persists_values(trend_file: Path) -> None:
    entry = record_entry(7, {"high": 7}, 4, trend_file=trend_file)
    assert entry.total_findings == 7
    assert entry.by_severity == {"high": 7}
    assert entry.scanned_files == 4


def test_record_entry_appends_multiple(trend_file: Path) -> None:
    record_entry(1, {}, 1, trend_file=trend_file)
    record_entry(3, {}, 2, trend_file=trend_file)
    entries = _load_entries(trend_file)
    assert len(entries) == 2
    assert entries[0].total_findings == 1
    assert entries[1].total_findings == 3


def test_load_trend_report_missing_file_returns_empty(trend_file: Path) -> None:
    report = load_trend_report(trend_file=trend_file)
    assert report.entries == []
    assert report.latest is None
    assert report.previous is None


def test_trend_report_delta_single_entry(trend_file: Path) -> None:
    record_entry(5, {}, 1, trend_file=trend_file)
    report = load_trend_report(trend_file=trend_file)
    assert report.delta() is None


def test_trend_report_delta_increase(trend_file: Path) -> None:
    record_entry(2, {}, 1, trend_file=trend_file)
    record_entry(5, {}, 1, trend_file=trend_file)
    report = load_trend_report(trend_file=trend_file)
    assert report.delta() == 3


def test_trend_report_delta_decrease(trend_file: Path) -> None:
    record_entry(8, {}, 1, trend_file=trend_file)
    record_entry(3, {}, 1, trend_file=trend_file)
    report = load_trend_report(trend_file=trend_file)
    assert report.delta() == -5


def test_trend_label_no_change(trend_file: Path) -> None:
    record_entry(4, {}, 1, trend_file=trend_file)
    record_entry(4, {}, 1, trend_file=trend_file)
    report = load_trend_report(trend_file=trend_file)
    assert "no change" in report.trend_label()


def test_trend_label_increase(trend_file: Path) -> None:
    record_entry(1, {}, 1, trend_file=trend_file)
    record_entry(6, {}, 1, trend_file=trend_file)
    label = load_trend_report(trend_file=trend_file).trend_label()
    assert "+5" in label


def test_trend_label_no_prior_data(trend_file: Path) -> None:
    report = load_trend_report(trend_file=trend_file)
    assert report.trend_label() == "no prior data"


def test_load_entries_corrupt_json_returns_empty(trend_file: Path) -> None:
    trend_file.parent.mkdir(parents=True, exist_ok=True)
    trend_file.write_text("not valid json", encoding="utf-8")
    assert _load_entries(trend_file) == []


def test_entry_round_trips_via_dict() -> None:
    entry = TrendEntry(
        timestamp="2024-01-01T00:00:00+00:00",
        total_findings=3,
        by_severity={"high": 1, "low": 2},
        scanned_files=5,
    )
    restored = TrendEntry.from_dict(entry.to_dict())
    assert restored.total_findings == entry.total_findings
    assert restored.by_severity == entry.by_severity
