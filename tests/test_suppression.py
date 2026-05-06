"""Tests for vaultmap.suppression."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vaultmap.suppression import (
    build_suppressed_lines,
    build_suppressed_lines_for_file,
    filter_suppressed,
)


def test_inline_tag_suppresses_line():
    source = 'secret = "abc"  # vaultmap: ignore\nother = "xyz"'
    result = build_suppressed_lines(source)
    assert 1 in result
    assert 2 not in result


def test_inline_tag_case_insensitive():
    source = 'key = "tok"  # VaultMap: IGNORE'
    result = build_suppressed_lines(source)
    assert 1 in result


def test_block_suppresses_range():
    source = "\n".join([
        "# vaultmap: ignore-start",
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'SECRET = "hunter2"',
        "# vaultmap: ignore-end",
        'normal = "ok"',
    ])
    result = build_suppressed_lines(source)
    assert result == frozenset({1, 2, 3, 4})
    assert 5 not in result


def test_empty_source_returns_empty_set():
    assert build_suppressed_lines("") == frozenset()


def test_no_tags_returns_empty_set():
    source = "x = 1\ny = 2\n"
    assert build_suppressed_lines(source) == frozenset()


def test_build_suppressed_lines_for_file(tmp_path: Path):
    f = tmp_path / "sample.py"
    f.write_text('token = "abc"  # vaultmap: ignore\nclean = 1\n')
    result = build_suppressed_lines_for_file(f)
    assert 1 in result
    assert 2 not in result


def test_build_suppressed_lines_for_file_missing(tmp_path: Path):
    missing = tmp_path / "nonexistent.py"
    assert build_suppressed_lines_for_file(missing) == frozenset()


def test_filter_suppressed_removes_matching_lines():
    matches = [
        SimpleNamespace(line_number=1),
        SimpleNamespace(line_number=3),
        SimpleNamespace(line_number=5),
    ]
    result = filter_suppressed(matches, frozenset({1, 5}))
    assert len(result) == 1
    assert result[0].line_number == 3


def test_filter_suppressed_empty_set_keeps_all():
    matches = [SimpleNamespace(line_number=n) for n in range(1, 6)]
    assert filter_suppressed(matches, frozenset()) == matches
