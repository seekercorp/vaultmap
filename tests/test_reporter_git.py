"""Tests for git-history reporting functions in vaultmap.reporter."""

from __future__ import annotations

import json

import pytest

from vaultmap.git_history import CommitMatch, GitScanResult
from vaultmap.reporter import print_git_json_report, print_git_text_report
from vaultmap.scanner import Match


def _make_match(**kwargs) -> Match:
    defaults = dict(
        file="app/config.py",
        line_number=3,
        line_content="SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        pattern_name="AWS Access Key",
        severity="critical",
        matched_value="AKIAIOSFODNN7EXAMPLE",
    )
    defaults.update(kwargs)
    return Match(**defaults)


@pytest.fixture()
def result_with_findings() -> GitScanResult:
    match = _make_match()
    cm = CommitMatch(
        commit_hash="deadbeef1234",
        commit_message="Add AWS credentials",
        file_path="app/config.py",
        matches=[match],
    )
    return GitScanResult(repo_path="/repo", commit_matches=[cm], commits_scanned=3)


@pytest.fixture()
def result_clean() -> GitScanResult:
    return GitScanResult(repo_path="/repo", commit_matches=[], commits_scanned=10)


def test_git_text_report_shows_commit(result_with_findings, capsys):
    print_git_text_report(result_with_findings)
    captured = capsys.readouterr().out
    assert "deadbeef1234" in captured
    assert "AWS Access Key" in captured


def test_git_text_report_clean(result_clean, capsys):
    print_git_text_report(result_clean)
    captured = capsys.readouterr().out
    assert "No credentials found" in captured
    assert "10" in captured


def test_git_json_report_structure(result_with_findings, capsys):
    print_git_json_report(result_with_findings)
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["repo_path"] == "/repo"
    assert data["commits_scanned"] == 3
    assert data["total_matches"] == 1
    assert len(data["commit_matches"]) == 1
    cm = data["commit_matches"][0]
    assert cm["commit_hash"] == "deadbeef1234"
    assert len(cm["matches"]) == 1
    assert cm["matches"][0]["severity"] == "critical"


def test_git_json_report_clean(result_clean, capsys):
    print_git_json_report(result_clean)
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["total_matches"] == 0
    assert data["commit_matches"] == []
