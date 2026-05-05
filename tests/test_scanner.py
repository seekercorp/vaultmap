"""Tests for the file and directory scanner."""

import textwrap
from pathlib import Path

import pytest

from vaultmap.scanner import scan_file, scan_directory, ScanResult


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a small fake repo structure for scanning tests."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(
        textwrap.dedent("""\
            AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
            DB_HOST = 'localhost'
        """)
    )
    (tmp_path / "src" / "clean.py").write_text(
        "def add(a, b):\n    return a + b\n"
    )
    (tmp_path / ".env").write_text(
        "password=supersecret123\nDEBUG=true\n"
    )
    # Binary-like file should be skipped
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
    return tmp_path


def test_scan_file_detects_aws_key(tmp_repo):
    matches = scan_file(tmp_repo / "src" / "config.py")
    pattern_names = [m.pattern.name for m in matches]
    assert "aws_access_key" in pattern_names


def test_scan_file_clean_returns_no_matches(tmp_repo):
    matches = scan_file(tmp_repo / "src" / "clean.py")
    assert matches == []


def test_scan_file_match_has_correct_line_number(tmp_repo):
    matches = scan_file(tmp_repo / "src" / "config.py")
    aws_matches = [m for m in matches if m.pattern.name == "aws_access_key"]
    assert aws_matches[0].line_number == 1


def test_scan_directory_counts_files(tmp_repo):
    result = scan_directory(tmp_repo)
    # src/config.py, src/clean.py, .env — image.png is excluded
    assert result.scanned_files == 3


def test_scan_directory_finds_findings(tmp_repo):
    result = scan_directory(tmp_repo)
    assert result.has_findings


def test_scan_directory_by_severity(tmp_repo):
    result = scan_directory(tmp_repo)
    high = result.by_severity("high")
    assert any(m.pattern.name == "aws_access_key" for m in high)


def test_scan_result_defaults():
    r = ScanResult()
    assert r.scanned_files == 0
    assert r.matches == []
    assert not r.has_findings
