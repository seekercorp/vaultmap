"""Tests for vaultmap.allowlist."""

import json
from pathlib import Path

import pytest

from vaultmap.allowlist import (
    Allowlist,
    AllowlistEntry,
    load_allowlist,
    DEFAULT_ALLOWLIST_PATH,
)


# ---------------------------------------------------------------------------
# AllowlistEntry
# ---------------------------------------------------------------------------

def test_entry_matches_value_exact():
    entry = AllowlistEntry(pattern=r"AKIAIOSFODNN7EXAMPLE", reason="test")
    assert entry.matches_value("AKIAIOSFODNN7EXAMPLE")


def test_entry_matches_value_regex():
    entry = AllowlistEntry(pattern=r"AKIA[A-Z0-9]{16}", reason="test")
    assert entry.matches_value("AKIAIOSFODNN7EXAMPLE")
    assert not entry.matches_value("ghp_notanawskey")


def test_entry_matches_path_empty_list_allows_all():
    entry = AllowlistEntry(pattern=r"secret", reason="test", paths=[])
    assert entry.matches_path("any/path/file.py")


def test_entry_matches_path_filters_correctly():
    entry = AllowlistEntry(pattern=r"secret", reason="test", paths=[r"tests/"])
    assert entry.matches_path("tests/fixtures/file.py")
    assert not entry.matches_path("src/main.py")


# ---------------------------------------------------------------------------
# Allowlist.is_allowed
# ---------------------------------------------------------------------------

def test_allowlist_is_allowed_true():
    al = Allowlist(entries=[
        AllowlistEntry(pattern=r"FAKE_KEY", reason="fixture", paths=[])
    ])
    assert al.is_allowed("FAKE_KEY", "tests/data.py")


def test_allowlist_is_allowed_false_no_entries():
    al = Allowlist.empty()
    assert not al.is_allowed("AKIAIOSFODNN7EXAMPLE", "src/config.py")


def test_allowlist_path_restricts_suppression():
    al = Allowlist(entries=[
        AllowlistEntry(pattern=r"FAKE_KEY", reason="fixture", paths=[r"tests/"])
    ])
    assert al.is_allowed("FAKE_KEY", "tests/conftest.py")
    assert not al.is_allowed("FAKE_KEY", "src/config.py")


# ---------------------------------------------------------------------------
# Allowlist.from_file
# ---------------------------------------------------------------------------

def test_from_file_loads_entries(tmp_path):
    cfg = tmp_path / "allowlist.json"
    cfg.write_text(json.dumps([
        {"pattern": "MY_SECRET", "reason": "example", "paths": ["tests/"]}
    ]))
    al = Allowlist.from_file(cfg)
    assert len(al.entries) == 1
    assert al.entries[0].reason == "example"


def test_from_file_missing_returns_empty(tmp_path):
    al = Allowlist.from_file(tmp_path / "nonexistent.json")
    assert al.entries == []


def test_from_file_minimal_entry(tmp_path):
    """Entries without optional keys should still parse."""
    cfg = tmp_path / "allowlist.json"
    cfg.write_text(json.dumps([{"pattern": "TOKEN", "reason": "ci"}]))
    al = Allowlist.from_file(cfg)
    assert al.entries[0].paths == []


# ---------------------------------------------------------------------------
# load_allowlist helper
# ---------------------------------------------------------------------------

def test_load_allowlist_uses_provided_path(tmp_path):
    cfg = tmp_path / "custom.json"
    cfg.write_text(json.dumps([{"pattern": "X", "reason": "r"}]))
    al = load_allowlist(cfg)
    assert len(al.entries) == 1


def test_load_allowlist_default_path_missing_returns_empty(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no .vaultmap-allowlist.json here
    al = load_allowlist()
    assert al.entries == []
