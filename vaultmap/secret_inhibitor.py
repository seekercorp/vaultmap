"""secret_inhibitor.py – suppress findings that match known-safe value fragments.

An *inhibitor* is a short literal or glob pattern that, when found anywhere
inside a matched secret value, marks the finding as inhibited (i.e. safe to
ignore).  Typical use-cases: test fixtures, placeholder tokens, and example
credentials embedded in documentation.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

from vaultmap.scanner import Match, ScanResult

# ---------------------------------------------------------------------------
# Built-in inhibitor fragments shipped with the library
# ---------------------------------------------------------------------------

DEFAULT_INHIBITORS: List[str] = [
    "example",
    "placeholder",
    "changeme",
    "your_*_here",
    "<*>",
    "xxxx*",
    "1234*",
    "test*secret",
    "dummy",
    "fake",
    "sample",
    "replace_me",
]


@dataclass
class InhibitedMatch:
    """A Match decorated with inhibition metadata."""

    match: Match
    inhibited: bool
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "inhibited": self.inhibited,
            "reason": self.reason,
            "path": self.match.path,
            "line": self.match.line,
            "pattern": self.match.pattern_name,
            "value": self.match.value,
        }


@dataclass
class InhibitedResult:
    """Wraps a ScanResult with per-match inhibition decisions."""

    source: ScanResult
    items: List[InhibitedMatch] = field(default_factory=list)

    @property
    def active(self) -> List[InhibitedMatch]:
        """Findings that are *not* inhibited."""
        return [i for i in self.items if not i.inhibited]

    @property
    def suppressed(self) -> List[InhibitedMatch]:
        """Findings that are inhibited."""
        return [i for i in self.items if i.inhibited]


def _is_inhibited(value: str, patterns: Sequence[str]) -> tuple[bool, str]:
    """Return (True, matching_pattern) if *value* matches any inhibitor."""
    lower = value.lower()
    for pat in patterns:
        if fnmatch.fnmatch(lower, f"*{pat.lower()}*"):
            return True, pat
    return False, ""


def inhibit_match(
    match: Match,
    extra_patterns: Iterable[str] = (),
) -> InhibitedMatch:
    """Evaluate a single match against the combined inhibitor list."""
    patterns = list(DEFAULT_INHIBITORS) + list(extra_patterns)
    hit, reason = _is_inhibited(match.value, patterns)
    return InhibitedMatch(match=match, inhibited=hit, reason=reason)


def inhibit_result(
    result: ScanResult,
    extra_patterns: Iterable[str] = (),
) -> InhibitedResult:
    """Apply inhibition logic to every match in *result*."""
    extra = list(extra_patterns)
    items = [inhibit_match(m, extra) for m in result.matches]
    return InhibitedResult(source=result, items=items)
