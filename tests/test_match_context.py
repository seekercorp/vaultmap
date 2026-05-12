"""Tests for vaultmap.match_context."""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from typing import Optional

import pytest

from vaultmap.match_context import (
    DEFAULT_CONTEXT_LINES,
    MatchContext,
    enrich_result_with_context,
    extract_context,
)


SOURCE_LINES = [
    "line1",
    "line2",
    "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
    "line4",
    "line5",
    "line6",
]


# ---------------------------------------------------------------------------
# extract_context
# ---------------------------------------------------------------------------


def test_extract_context_returns_matched_line():
    ctx = extract_context("fake.py", 3, lines=SOURCE_LINES)
    assert ctx.matched == "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"


def test_extract_context_before_lines():
    ctx = extract_context("fake.py", 3, lines=SOURCE_LINES)
    assert ctx.before == ["line1", "line2"]


def test_extract_context_after_lines():
    ctx = extract_context("fake.py", 3, lines=SOURCE_LINES)
    assert ctx.after == ["line4", "line5"]


def test_extract_context_first_line_no_before():
    ctx = extract_context("fake.py", 1, lines=SOURCE_LINES)
    assert ctx.before == []
    assert ctx.matched == "line1"


def test_extract_context_last_line_no_after():
    ctx = extract_context("fake.py", 6, lines=SOURCE_LINES)
    assert ctx.after == []
    assert ctx.matched == "line6"


def test_extract_context_custom_window():
    ctx = extract_context("fake.py", 3, lines=SOURCE_LINES, context_lines=1)
    assert ctx.before == ["line2"]
    assert ctx.after == ["line4"]


def test_extract_context_missing_file_returns_empty():
    ctx = extract_context("/nonexistent/path.py", 1)
    assert ctx.matched == ""
    assert ctx.before == []
    assert ctx.after == []


def test_extract_context_reads_real_file(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("alpha\nbeta\ngamma\n")
    ctx = extract_context(str(f), 2)
    assert ctx.matched == "beta"
    assert ctx.before == ["alpha"]
    assert ctx.after == ["gamma"]


# ---------------------------------------------------------------------------
# MatchContext.to_dict
# ---------------------------------------------------------------------------


def test_match_context_to_dict():
    ctx = MatchContext(
        path="secrets.env",
        line_number=5,
        before=["a"],
        matched="SECRET=xyz",
        after=["b"],
    )
    d = ctx.to_dict()
    assert d["path"] == "secrets.env"
    assert d["line_number"] == 5
    assert d["matched"] == "SECRET=xyz"


# ---------------------------------------------------------------------------
# enrich_result_with_context
# ---------------------------------------------------------------------------


@dataclass
class _FakeMatch:
    path: str
    line_number: int


def test_enrich_result_with_context_length(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("\n".join(SOURCE_LINES))
    matches = [_FakeMatch(str(f), 3), _FakeMatch(str(f), 5)]
    contexts = enrich_result_with_context(matches)
    assert len(contexts) == 2


def test_enrich_result_caches_file_reads(tmp_path, monkeypatch):
    """File should only be read once even if multiple matches share a path."""
    f = tmp_path / "code.py"
    f.write_text("\n".join(SOURCE_LINES))
    read_count = {"n": 0}
    original_read = Path.read_text

    def counting_read(self, *args, **kwargs):
        if str(self) == str(f):
            read_count["n"] += 1
        return original_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting_read)
    matches = [_FakeMatch(str(f), 1), _FakeMatch(str(f), 2), _FakeMatch(str(f), 3)]
    enrich_result_with_context(matches)
    assert read_count["n"] == 1
