"""Tests for the vaultmap CLI entry point."""

import json
from pathlib import Path

import pytest

from vaultmap.cli import main, build_parser, _severity_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeMatch:
    def __init__(self, severity="high"):
        self.severity = severity


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.path == "."
    assert args.format == "text"
    assert args.git is False
    assert args.severity is None
    assert args.max_commits == 100


def test_build_parser_all_flags():
    parser = build_parser()
    args = parser.parse_args(["/tmp", "--git", "--format", "json", "--severity", "high", "--max-commits", "50"])
    assert args.path == "/tmp"
    assert args.git is True
    assert args.format == "json"
    assert args.severity == "high"
    assert args.max_commits == 50


# ---------------------------------------------------------------------------
# Severity filter tests
# ---------------------------------------------------------------------------

def test_severity_filter_keeps_equal():
    keep = _severity_filter("high")
    assert keep(_FakeMatch("high")) is True


def test_severity_filter_keeps_above():
    keep = _severity_filter("medium")
    assert keep(_FakeMatch("critical")) is True


def test_severity_filter_drops_below():
    keep = _severity_filter("high")
    assert keep(_FakeMatch("low")) is False


# ---------------------------------------------------------------------------
# Integration: exit codes
# ---------------------------------------------------------------------------

def test_main_clean_directory_exits_zero(tmp_path):
    (tmp_path / "hello.py").write_text("print('hello world')\n")
    code = main([str(tmp_path)])
    assert code == 0


def test_main_with_finding_exits_one(tmp_path):
    (tmp_path / "secrets.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    code = main([str(tmp_path)])
    assert code == 1


def test_main_json_format_clean(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("x = 1\n")
    main([str(tmp_path), "--format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "findings" in data or "files_scanned" in data


def test_main_single_file_clean_exits_zero(tmp_path):
    f = tmp_path / "ok.py"
    f.write_text("# nothing secret here\n")
    code = main([str(f)])
    assert code == 0
