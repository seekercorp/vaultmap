"""secret_fingerprinter.py – produce stable, human-readable fingerprints for
every Match so findings can be referenced consistently across runs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Sequence

from vaultmap.scanner import Match, ScanResult


@dataclass
class FingerprintedMatch:
    """A Match decorated with a short, stable fingerprint string."""

    match: Match
    fingerprint: str
    short_id: str  # first 8 hex chars – suitable for display

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "short_id": self.short_id,
            "path": self.match.path,
            "line": self.match.line,
            "pattern": self.match.pattern_name,
            "severity": self.match.severity,
            "value": self.match.value,
        }


@dataclass
class FingerprintedResult:
    """Wraps a ScanResult with fingerprinted matches."""

    source: ScanResult
    matches: List[FingerprintedMatch] = field(default_factory=list)

    def by_short_id(self, short_id: str) -> FingerprintedMatch | None:
        """Look up a match by its 8-char short id."""
        for m in self.matches:
            if m.short_id == short_id:
                return m
        return None


def _stable_fingerprint(match: Match) -> str:
    """Return a SHA-256 hex digest that is stable across runs.

    The digest is derived from path, line number, pattern name, and the
    *normalised* value (leading/trailing whitespace stripped, interior
    whitespace collapsed) so minor formatting changes do not invalidate it.
    """
    normalised_value = re.sub(r"\s+", " ", match.value.strip())
    raw = "\x00".join(
        [
            match.path,
            str(match.line),
            match.pattern_name,
            normalised_value,
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def fingerprint_match(match: Match) -> FingerprintedMatch:
    """Decorate a single Match with its fingerprint."""
    fp = _stable_fingerprint(match)
    return FingerprintedMatch(match=match, fingerprint=fp, short_id=fp[:8])


def fingerprint_result(result: ScanResult) -> FingerprintedResult:
    """Return a FingerprintedResult for all matches in *result*."""
    fingerprinted = [fingerprint_match(m) for m in result.matches]
    return FingerprintedResult(source=result, matches=fingerprinted)


def unique_fingerprints(matches: Sequence[FingerprintedMatch]) -> List[str]:
    """Return a sorted, deduplicated list of fingerprint strings."""
    return sorted({m.fingerprint for m in matches})
