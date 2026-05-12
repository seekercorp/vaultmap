"""Tests for vaultmap.diff_reporter."""
from __future__ import annotations

import io
import json

from vaultmap.scanner import Match
from vaultmap.match_diff import DiffReport
from vaultmap.diff_reporter import print_diff_text_report, print_diff_json_report


def _make_match(path="app.py", line=5, pattern="github_token", value="ghp_abc", severity="high") -> Match:
    return Match(
        path=path,
        line_number=line,
        pattern_name=pattern,
        value=value,
        severity=severity,
        matched_line=f"token={value}",
    )


def test_text_report_shows_new_findings():
    m = _make_match()
    report = DiffReport(new_matches=[m], resolved_matches=[], persisted_count=0)
    buf = io.StringIO()
    print_diff_text_report(report, out=buf, use_color=False)
    output = buf.getvalue()
    assert "[+]" in output
    assert "github_token" in output


def test_text_report_shows_resolved():
    m = _make_match()
    report = DiffReport(new_matches=[], resolved_matches=[m], persisted_count=1)
    buf = io.StringIO()
    print_diff_text_report(report, out=buf, use_color=False)
    output = buf.getvalue()
    assert "[-]" in output


def test_text_report_no_changes_message():
    report = DiffReport(new_matches=[], resolved_matches=[], persisted_count=2)
    buf = io.StringIO()
    print_diff_text_report(report, out=buf, use_color=False)
    output = buf.getvalue()
    assert "No changes" in output


def test_json_report_structure():
    m = _make_match()
    report = DiffReport(new_matches=[m], resolved_matches=[], persisted_count=3)
    buf = io.StringIO()
    print_diff_json_report(report, out=buf)
    data = json.loads(buf.getvalue())
    assert "new" in data
    assert "resolved" in data
    assert "persisted_count" in data
    assert data["persisted_count"] == 3
    assert len(data["new"]) == 1
    assert data["new"][0]["pattern_name"] == "github_token"


def test_json_report_resolved_populated():
    m = _make_match(line=99)
    report = DiffReport(new_matches=[], resolved_matches=[m], persisted_count=0)
    buf = io.StringIO()
    print_diff_json_report(report, out=buf)
    data = json.loads(buf.getvalue())
    assert len(data["resolved"]) == 1
    assert data["resolved"][0]["line_number"] == 99


def test_json_report_summary_key_present():
    report = DiffReport(new_matches=[], resolved_matches=[], persisted_count=0)
    buf = io.StringIO()
    print_diff_json_report(report, out=buf)
    data = json.loads(buf.getvalue())
    assert "summary" in data
