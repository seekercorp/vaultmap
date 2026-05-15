"""Tests for vaultmap.relay_reporter."""
from __future__ import annotations

import json
from io import StringIO
import sys

import pytest

from vaultmap.secret_relay import RelayRecord, RelayReport
from vaultmap.relay_reporter import print_relay_text_report, print_relay_json_report


def _ok(path: str = "src/a.py", line: int = 1) -> RelayRecord:
    return RelayRecord(path=path, line=line, pattern="aws_key", severity="critical",
                       value=None, status_code=200)


def _fail(path: str = "src/b.py", line: int = 2) -> RelayRecord:
    return RelayRecord(path=path, line=line, pattern="gh_token", severity="high",
                       value=None, error="connection refused")


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        fn(*args, **kwargs)
    finally:
        sys.stdout = old
    return buf.getvalue()


def test_text_report_empty_says_no_findings():
    out = _capture(print_relay_text_report, RelayReport(), colour=False)
    assert "No findings" in out


def test_text_report_shows_summary_line():
    report = RelayReport(records=[_ok(), _fail()])
    out = _capture(print_relay_text_report, report, colour=False)
    assert "1 sent" in out
    assert "1 failed" in out


def test_text_report_shows_each_record():
    report = RelayReport(records=[_ok("src/secret.py", 42)])
    out = _capture(print_relay_text_report, report, colour=False)
    assert "src/secret.py" in out
    assert "42" in out


def test_text_report_shows_fail_error():
    report = RelayReport(records=[_fail()])
    out = _capture(print_relay_text_report, report, colour=False)
    assert "connection refused" in out


def test_json_report_structure():
    report = RelayReport(records=[_ok(), _fail()])
    out = _capture(print_relay_json_report, report)
    data = json.loads(out)
    assert data["sent"] == 1
    assert data["failed"] == 1
    assert len(data["records"]) == 2


def test_json_report_record_keys():
    report = RelayReport(records=[_ok()])
    out = _capture(print_relay_json_report, report)
    rec = json.loads(out)["records"][0]
    for key in ("path", "line", "pattern", "severity", "status_code", "error"):
        assert key in rec
