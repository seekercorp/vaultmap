"""Normalize matched secret values for consistent comparison and display."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from vaultmap.scanner import Match, ScanResult


_WHITESPACE_RE = re.compile(r"\s+")
_QUOTE_RE = re.compile(r'^[\'"]|[\'"]$')
_ASSIGNMENT_RE = re.compile(r'^[^=:]+[=:]\s*')


@dataclass
class NormalizedMatch:
    original: Match
    normalized_value: str
    transformations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.original.path,
            "line": self.original.line,
            "pattern": self.original.pattern_name,
            "severity": self.original.severity,
            "original_value": self.original.value,
            "normalized_value": self.normalized_value,
            "transformations": self.transformations,
        }


@dataclass
class NormalizedResult:
    matches: List[NormalizedMatch] = field(default_factory=list)
    scanned_files: int = 0


def normalize_value(raw: str) -> tuple[str, List[str]]:
    """Strip common noise from a matched value; return (clean, transformations)."""
    value = raw
    applied: List[str] = []

    # Strip leading assignment prefix (e.g. 'KEY = ')
    stripped = _ASSIGNMENT_RE.sub("", value)
    if stripped != value:
        value = stripped
        applied.append("strip_assignment")

    # Strip surrounding quotes
    unquoted = _QUOTE_RE.sub("", value)
    if unquoted != value:
        value = unquoted
        applied.append("strip_quotes")

    # Collapse internal whitespace
    collapsed = _WHITESPACE_RE.sub("", value)
    if collapsed != value:
        value = collapsed
        applied.append("collapse_whitespace")

    return value, applied


def normalize_match(match: Match) -> NormalizedMatch:
    """Produce a NormalizedMatch from a raw Match."""
    clean, transforms = normalize_value(match.value)
    return NormalizedMatch(
        original=match,
        normalized_value=clean,
        transformations=transforms,
    )


def normalize_result(result: ScanResult) -> NormalizedResult:
    """Normalize all matches in a ScanResult."""
    return NormalizedResult(
        matches=[normalize_match(m) for m in result.matches],
        scanned_files=result.scanned_files,
    )
