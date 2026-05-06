"""Inline suppression support for vaultmap.

Lines or blocks annotated with  # vaultmap: ignore  are skipped during
file scanning.  A trailing comment on the same line is sufficient.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

_INLINE_TAG = re.compile(r"#\s*vaultmap:\s*ignore", re.IGNORECASE)
_BLOCK_START = re.compile(r"#\s*vaultmap:\s*ignore-start", re.IGNORECASE)
_BLOCK_END = re.compile(r"#\s*vaultmap:\s*ignore-end", re.IGNORECASE)


def build_suppressed_lines(source: str) -> frozenset[int]:
    """Return a frozenset of 1-based line numbers that are suppressed.

    Supports two forms:
    * Inline:  ``secret = "abc"  # vaultmap: ignore``
    * Block:   ``# vaultmap: ignore-start`` … ``# vaultmap: ignore-end``
    """
    suppressed: set[int] = set()
    in_block = False

    for lineno, line in enumerate(source.splitlines(), start=1):
        if _BLOCK_START.search(line):
            in_block = True
            suppressed.add(lineno)
            continue
        if _BLOCK_END.search(line):
            in_block = False
            suppressed.add(lineno)
            continue
        if in_block or _INLINE_TAG.search(line):
            suppressed.add(lineno)

    return frozenset(suppressed)


def build_suppressed_lines_for_file(path: Path) -> frozenset[int]:
    """Read *path* and return its suppressed line numbers."""
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return frozenset()
    return build_suppressed_lines(source)


def filter_suppressed(
    matches: Iterable,
    suppressed: frozenset[int],
) -> list:
    """Remove Match objects whose line number appears in *suppressed*."""
    return [m for m in matches if m.line_number not in suppressed]
