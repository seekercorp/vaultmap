"""Tests for vaultmap.ignore_rules."""

import textwrap
from pathlib import Path

import pytest

from vaultmap.ignore_rules import (
    DEFAULT_IGNORE_PATTERNS,
    IgnoreRules,
    build_ignore_rules,
    load_ignore_file,
)


# ---------------------------------------------------------------------------
# IgnoreRules.is_ignored
# ---------------------------------------------------------------------------

def test_default_patterns_ignore_git_dir():
    rules = IgnoreRules()
    assert rules.is_ignored(".git/config")


def test_default_patterns_ignore_pycache():
    rules = IgnoreRules()
    assert rules.is_ignored("src/__pycache__/module.cpython-311.pyc")


def test_default_patterns_ignore_pyc_by_extension():
    rules = IgnoreRules()
    assert rules.is_ignored("vaultmap/scanner.pyc")


def test_default_patterns_ignore_node_modules():
    rules = IgnoreRules()
    assert rules.is_ignored("node_modules/lodash/index.js")


def test_regular_source_file_not_ignored():
    rules = IgnoreRules()
    assert not rules.is_ignored("vaultmap/scanner.py")


def test_custom_pattern_respected():
    rules = IgnoreRules(patterns=["secrets/**"])
    assert rules.is_ignored("secrets/prod.env")
    assert not rules.is_ignored("config/prod.env")


def test_use_defaults_false_skips_defaults():
    rules = IgnoreRules(use_defaults=False)
    # .git/config would normally be ignored but defaults are off
    assert not rules.is_ignored(".git/config")


def test_use_defaults_false_still_applies_custom():
    rules = IgnoreRules(patterns=["*.log"], use_defaults=False)
    assert rules.is_ignored("app.log")
    assert not rules.is_ignored("app.py")


# ---------------------------------------------------------------------------
# IgnoreRules.filter
# ---------------------------------------------------------------------------

def test_filter_removes_ignored_paths():
    rules = IgnoreRules(patterns=["*.log"], use_defaults=False)
    paths = ["main.py", "error.log", "README.md"]
    assert rules.filter(paths) == ["main.py", "README.md"]


def test_filter_empty_list_returns_empty():
    rules = IgnoreRules()
    assert rules.filter([]) == []


# ---------------------------------------------------------------------------
# load_ignore_file
# ---------------------------------------------------------------------------

def test_load_ignore_file_parses_patterns(tmp_path):
    ignore = tmp_path / ".vaultmapignore"
    ignore.write_text(textwrap.dedent("""\
        # this is a comment
        secrets/**
        *.bak

        # another comment
        tmp/
    """))
    patterns = load_ignore_file(ignore)
    assert patterns == ["secrets/**", "*.bak", "tmp/"]


def test_load_ignore_file_missing_returns_empty(tmp_path):
    patterns = load_ignore_file(tmp_path / "nonexistent")
    assert patterns == []


# ---------------------------------------------------------------------------
# build_ignore_rules
# ---------------------------------------------------------------------------

def test_build_ignore_rules_merges_file_and_extra(tmp_path):
    ignore = tmp_path / ".vaultmapignore"
    ignore.write_text("secrets/**\n")
    rules = build_ignore_rules(extra_patterns=["*.bak"], ignore_file=ignore)
    assert rules.is_ignored("secrets/key.pem")
    assert rules.is_ignored("backup.bak")


def test_build_ignore_rules_no_file_no_extra():
    rules = build_ignore_rules()
    # Defaults still active
    assert rules.is_ignored(".git/HEAD")
