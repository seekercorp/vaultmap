"""Tests for vaultmap.secret_snapshot and snapshot_reporter."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from vaultmap.secret_snapshot import (
    Snapshot,
    SnapshotEntry,
    capture_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)
from vaultmap.scanner import ScanResult


class _FakeMatch:
    def __init__(self, path, pattern_name, line_number, value, severity):
        self.path = path
        self.pattern_name = pattern_name
        self.line_number = line_number
        self.value = value
        self.severity = severity


def _make_result(*matches):
    result = ScanResult.__new__(ScanResult)
    result.matches = list(matches)
    result.files_scanned = len(matches)
    return result


def _make_match(path="src/app.py", pattern_name="aws_access_key", line_number=10,
                value="AKIAIOSFODNN7EXAMPLE", severity="critical"):
    return _FakeMatch(path, pattern_name, line_number, value, severity)


# ── SnapshotEntry ────────────────────────────────────────────────────────────

def test_snapshot_entry_to_dict_keys():
    e = SnapshotEntry("a.py", "pat", 1, "val", "high", 1000.0)
    d = e.to_dict()
    assert set(d.keys()) == {"path", "pattern_name", "line_number", "value", "severity", "captured_at"}


def test_snapshot_entry_roundtrip():
    e = SnapshotEntry("a.py", "pat", 5, "secret", "critical", 9999.0)
    assert SnapshotEntry.from_dict(e.to_dict()) == e


# ── capture_snapshot ─────────────────────────────────────────────────────────

def test_capture_snapshot_entry_count():
    result = _make_result(_make_match(), _make_match(line_number=20))
    snap = capture_snapshot(result, label="v1")
    assert snap.count == 2
    assert snap.label == "v1"


def test_capture_snapshot_empty_result():
    result = _make_result()
    snap = capture_snapshot(result, label="empty")
    assert snap.count == 0


def test_capture_snapshot_entry_fields():
    m = _make_match()
    snap = capture_snapshot(_make_result(m), label="x")
    e = snap.entries[0]
    assert e.path == m.path
    assert e.pattern_name == m.pattern_name
    assert e.line_number == m.line_number
    assert e.value == m.value
    assert e.severity == m.severity


# ── save / load ───────────────────────────────────────────────────────────────

def test_save_and_load_snapshot(tmp_path):
    snap = capture_snapshot(_make_result(_make_match()), label="persist")
    dest = tmp_path / "snap.json"
    save_snapshot(snap, dest)
    loaded = load_snapshot(dest)
    assert loaded is not None
    assert loaded.label == snap.label
    assert loaded.count == snap.count


def test_load_snapshot_missing_returns_none(tmp_path):
    assert load_snapshot(tmp_path / "nonexistent.json") is None


# ── diff_snapshots ────────────────────────────────────────────────────────────

def test_diff_identical_snapshots():
    m = _make_match()
    snap = capture_snapshot(_make_result(m), label="a")
    diff = diff_snapshots(snap, snap)
    assert len(diff["added"]) == 0
    assert len(diff["removed"]) == 0
    assert len(diff["unchanged"]) == 1


def test_diff_detects_new_entry():
    before = capture_snapshot(_make_result(), label="before")
    after = capture_snapshot(_make_result(_make_match()), label="after")
    diff = diff_snapshots(before, after)
    assert len(diff["added"]) == 1
    assert len(diff["removed"]) == 0


def test_diff_detects_removed_entry():
    before = capture_snapshot(_make_result(_make_match()), label="before")
    after = capture_snapshot(_make_result(), label="after")
    diff = diff_snapshots(before, after)
    assert len(diff["removed"]) == 1
    assert len(diff["added"]) == 0
