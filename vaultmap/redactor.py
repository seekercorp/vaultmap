"""Redactor: mask sensitive credential values in scan output."""

from __future__ import annotations

import re
from typing import List

from vaultmap.scanner import Match, ScanResult

# Number of characters to reveal at each end of a secret value.
_REVEAL_CHARS = 4
_MASK_CHAR = "*"
_MIN_MASK_LENGTH = 8


def redact_value(value: str, reveal: int = _REVEAL_CHARS) -> str:
    """Return a partially-masked version of *value*.

    The first and last *reveal* characters are kept; the middle is
    replaced with asterisks.  Very short values are fully masked.

    >>> redact_value("AKIAIOSFODNN7EXAMPLE")
    'AKIA************MPLE'
    """
    if len(value) <= reveal * 2:
        return _MASK_CHAR * max(_MIN_MASK_LENGTH, len(value))
    middle_len = len(value) - reveal * 2
    return value[:reveal] + _MASK_CHAR * middle_len + value[-reveal:]


def redact_line(line: str, value: str) -> str:
    """Replace every literal occurrence of *value* inside *line* with its
    redacted form.  The replacement is case-sensitive."""
    if not value:
        return line
    return line.replace(value, redact_value(value))


def redact_match(match: Match) -> Match:
    """Return a new :class:`~vaultmap.scanner.Match` with the secret value
    and the surrounding line context redacted."""
    redacted_value = redact_value(match.value)
    redacted_line = redact_line(match.line_content, match.value)
    return Match(
        path=match.path,
        line_number=match.line_number,
        pattern_name=match.pattern_name,
        severity=match.severity,
        value=redacted_value,
        line_content=redacted_line,
    )


def redact_result(result: ScanResult) -> ScanResult:
    """Return a new :class:`~vaultmap.scanner.ScanResult` where every match
    has its secret value redacted."""
    redacted_matches: List[Match] = [redact_match(m) for m in result.matches]
    return ScanResult(
        files_scanned=result.files_scanned,
        matches=redacted_matches,
    )
