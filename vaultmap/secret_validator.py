"""secret_validator.py — Lightweight heuristic validation of matched secrets.

Attempts to distinguish likely-real credentials from test/placeholder values
without making any network calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from vaultmap.scanner import Match, ScanResult

# Strings that strongly suggest a value is a placeholder, not a real secret.
_PLACEHOLDER_FRAGMENTS = [
    "example",
    "placeholder",
    "your_",
    "<your",
    "xxxx",
    "1234567890",
    "abcdefgh",
    "test",
    "dummy",
    "fake",
    "changeme",
    "insert_",
    "replace_",
    "todo",
]

# Minimum length a secret value should have to be considered plausible.
_MIN_SECRET_LENGTH = 8


@dataclass
class ValidatedMatch:
    match: Match
    is_plausible: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "path": self.match.path,
            "line": self.match.line_number,
            "pattern": self.match.pattern_name,
            "value": self.match.value,
            "is_plausible": self.is_plausible,
            "reason": self.reason,
        }


def validate_match(match: Match) -> ValidatedMatch:
    """Apply heuristic checks to a single Match and return a ValidatedMatch."""
    value = match.value.strip()

    if len(value) < _MIN_SECRET_LENGTH:
        return ValidatedMatch(match, False, "value too short")

    lower = value.lower()
    for fragment in _PLACEHOLDER_FRAGMENTS:
        if fragment in lower:
            return ValidatedMatch(match, False, f"placeholder fragment '{fragment}'")

    # Reject values that are entirely one repeated character (e.g. "aaaaaaaaaa")
    if len(set(value)) == 1:
        return ValidatedMatch(match, False, "uniform character repetition")

    return ValidatedMatch(match, True, "passed heuristic checks")


def validate_result(result: ScanResult) -> List[ValidatedMatch]:
    """Validate all matches in a ScanResult and return a list of ValidatedMatch."""
    return [validate_match(m) for m in result.matches]


def plausible_only(validated: List[ValidatedMatch]) -> List[ValidatedMatch]:
    """Filter a list of ValidatedMatch to only plausible entries."""
    return [v for v in validated if v.is_plausible]
