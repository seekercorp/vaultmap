"""Deduplication utilities for scan matches.

Provides helpers to collapse duplicate findings that share the same
pattern, value, and file path — useful when the same credential
appears on multiple lines or is caught by overlapping patterns.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, List

from vaultmap.scanner import Match, ScanResult


def _dedup_key(match: Match) -> tuple:
    """Return a hashable key that identifies a logically duplicate match.

    Two matches are considered duplicates when they share the same
    pattern name, matched value, and file path.  Line number is
    intentionally excluded so that copy-pasted credentials collapsed
    into a single representative finding.
    """
    return (match.pattern_name, match.value, match.path)


def deduplicate_matches(matches: Iterable[Match]) -> List[Match]:
    """Return a list of matches with duplicates removed.

    The *first* occurrence (lowest line number) is kept for each
    unique (pattern_name, value, path) triple.
    """
    seen: dict[tuple, Match] = {}
    for match in matches:
        key = _dedup_key(match)
        if key not in seen:
            seen[key] = match
        else:
            # Keep the match with the smaller line number
            if match.line < seen[key].line:
                seen[key] = match
    return list(seen.values())


def deduplicate_result(result: ScanResult) -> ScanResult:
    """Return a new ScanResult with duplicate matches removed.

    All other fields (files_scanned, errors) are preserved unchanged.
    """
    deduped = deduplicate_matches(result.matches)
    return ScanResult(
        matches=deduped,
        files_scanned=result.files_scanned,
        errors=result.errors,
    )


def duplicate_summary(matches: Iterable[Match]) -> dict[tuple, int]:
    """Return a mapping of dedup-key -> count for diagnostic purposes."""
    counts: dict[tuple, int] = defaultdict(int)
    for match in matches:
        counts[_dedup_key(match)] += 1
    return dict(counts)
