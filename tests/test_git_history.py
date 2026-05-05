"""Tests for vaultmap.git_history module."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vaultmap.git_history import (
    CommitMatch,
    GitScanResult,
    _get_commit_diff,
    _iter_commits,
    scan_git_history,
)
from vaultmap.scanner import Match


FAKE_LOG = "abc123def456 Add config file\n789xyz000aaa Initial commit\n"

FAKE_DIFF = """\
diff --git a/config.py b/config.py
index 0000000..1111111 100644
--- a/config.py
+++ b/config.py
@@ -0,0 +1,2 @@
+AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
+SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
"""


@pytest.fixture()
def fake_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@test.com"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"],
                   check=True, capture_output=True)
    secret_file = tmp_path / "secrets.py"
    secret_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "add secrets"],
                   check=True, capture_output=True)
    return tmp_path


def test_git_scan_result_has_findings():
    match = Match(file="f", line_number=1, line_content="x",
                  pattern_name="p", severity="high", matched_value="v")
    cm = CommitMatch(commit_hash="abc", commit_message="msg", file_path="f", matches=[match])
    result = GitScanResult(repo_path="/tmp", commit_matches=[cm], commits_scanned=1)
    assert result.has_findings is True
    assert result.total_matches == 1


def test_git_scan_result_no_findings():
    result = GitScanResult(repo_path="/tmp", commit_matches=[], commits_scanned=5)
    assert result.has_findings is False
    assert result.total_matches == 0


@patch("vaultmap.git_history.subprocess.run")
def test_iter_commits_parses_output(mock_run):
    mock_run.return_value = MagicMock(stdout=FAKE_LOG, returncode=0)
    commits = list(_iter_commits(Path("/fake"), max_commits=10))
    assert len(commits) == 2
    assert commits[0] == ("abc123def456", "Add config file")
    assert commits[1] == ("789xyz000aaa", "Initial commit")


@patch("vaultmap.git_history.subprocess.run")
def test_get_commit_diff_returns_stdout(mock_run):
    mock_run.return_value = MagicMock(stdout=FAKE_DIFF)
    diff = _get_commit_diff(Path("/fake"), "abc123")
    assert "+++ b/config.py" in diff
    assert "AKIAIOSFODNN7EXAMPLE" in diff


def test_scan_git_history_real_repo(fake_repo: Path):
    result = scan_git_history(fake_repo)
    assert result.commits_scanned >= 1
    assert isinstance(result.has_findings, bool)


def test_scan_git_history_finds_aws_key(fake_repo: Path):
    result = scan_git_history(fake_repo)
    all_pattern_names = [
        m.pattern_name for cm in result.commit_matches for m in cm.matches
    ]
    assert any("aws" in name.lower() or "AWS" in name for name in all_pattern_names)
