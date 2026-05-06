"""Tests for vaultmap.audit_log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vaultmap.audit_log import log_scan, log_git_scan, load_audit_log
from vaultmap.scanner import ScanResult, Match
from vaultmap.git_history import GitScanResult, CommitMatch


def _make_scan_result(files: int = 3, findings: dict | None = None) -> ScanResult:
    matches = findings or {}
    return ScanResult(scanned_files=files, matches=matches)


def _make_match(value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(
        pattern_name="aws_access_key",
        severity="critical",
        file_path="config.py",
        line_number=1,
        line_content=f'key = "{value}"',
        matched_value=value,
    )


def _make_git_result(with_findings: bool = True) -> GitScanResult:
    m = _make_match() if with_findings else None
    cm = CommitMatch(
        commit_hash="abc123",
        author="dev",
        date="2024-01-01",
        message="add key",
        matches=[m] if m else [],
    )
    return GitScanResult(commit_matches=[cm])


def test_log_scan_writes_record(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    result = _make_scan_result(files=5, findings={"a.py": [_make_match()]})
    log_scan(result, log_file=log)
    records = load_audit_log(log_file=log)
    assert len(records) == 1
    rec = records[0]
    assert rec["event"] == "scan"
    assert rec["scanned_files"] == 5
    assert rec["total_matches"] == 1
    assert "a.py" in rec["files_with_findings"]


def test_log_git_scan_writes_record(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    result = _make_git_result(with_findings=True)
    log_git_scan(result, log_file=log)
    records = load_audit_log(log_file=log)
    assert len(records) == 1
    rec = records[0]
    assert rec["event"] == "git_scan"
    assert rec["commits_scanned"] == 1
    assert rec["total_matches"] == 1
    assert "abc123" in rec["commits_with_findings"]


def test_log_scan_no_path_does_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULTMAP_AUDIT_LOG", raising=False)
    result = _make_scan_result()
    log_scan(result)  # no log_file, no env var — must not raise
    assert load_audit_log() == []


def test_multiple_records_appended(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    r1 = _make_scan_result(files=2)
    r2 = _make_scan_result(files=7)
    log_scan(r1, log_file=log)
    log_scan(r2, log_file=log)
    records = load_audit_log(log_file=log)
    assert len(records) == 2
    assert records[0]["scanned_files"] == 2
    assert records[1]["scanned_files"] == 7


def test_load_audit_log_missing_file_returns_empty(tmp_path):
    log = str(tmp_path / "nonexistent.jsonl")
    assert load_audit_log(log_file=log) == []


def test_timestamp_is_iso_format(tmp_path):
    from datetime import datetime
    log = str(tmp_path / "audit.jsonl")
    log_scan(_make_scan_result(), log_file=log)
    records = load_audit_log(log_file=log)
    ts = records[0]["timestamp"]
    # Should parse without error
    datetime.fromisoformat(ts)
