"""Composite scoring of matches combining risk, entropy, validation, and severity."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from vaultmap.scanner import Match, ScanResult

# Weight table: each dimension contributes a fraction of the final 0-100 score.
_SEVERITY_SCORES = {"critical": 40, "high": 30, "medium": 20, "low": 10}
_ENTROPY_BONUS_THRESHOLD = 4.0  # bits
_ENTROPY_BONUS = 10
_VALIDATION_BONUS = 15  # plausible secret
_PATH_BONUS = 10  # sensitive path
_SENSITIVE_PATH_FRAGMENTS = (".env", "secret", "credential", "password", "key", "token")


@dataclass(frozen=True)
class ScoredMatch:
    match: Match
    score: int  # 0-100
    breakdown: dict

    def to_dict(self) -> dict:
        return {
            "path": self.match.path,
            "line": self.match.line_number,
            "pattern": self.match.pattern_name,
            "score": self.score,
            "breakdown": self.breakdown,
        }


@dataclass
class ScoredResult:
    scored: List[ScoredMatch]
    source_result: ScanResult

    def top(self, n: int = 10) -> List[ScoredMatch]:
        return sorted(self.scored, key=lambda s: s.score, reverse=True)[:n]

    def above(self, threshold: int) -> List[ScoredMatch]:
        return [s for s in self.scored if s.score >= threshold]


def _score_match(match: Match, entropy: float = 0.0, plausible: bool = False) -> ScoredMatch:
    breakdown: dict = {}

    severity_pts = _SEVERITY_SCORES.get(getattr(match, "severity", "low"), 10)
    breakdown["severity"] = severity_pts

    entropy_pts = _ENTROPY_BONUS if entropy >= _ENTROPY_BONUS_THRESHOLD else 0
    breakdown["entropy"] = entropy_pts

    validation_pts = _VALIDATION_BONUS if plausible else 0
    breakdown["validation"] = validation_pts

    path_lower = (match.path or "").lower()
    path_pts = _PATH_BONUS if any(f in path_lower for f in _SENSITIVE_PATH_FRAGMENTS) else 0
    breakdown["path"] = path_pts

    total = min(severity_pts + entropy_pts + validation_pts + path_pts, 100)
    return ScoredMatch(match=match, score=total, breakdown=breakdown)


def score_result(
    result: ScanResult,
    entropy_map: dict | None = None,
    plausible_set: set | None = None,
) -> ScoredResult:
    """Score every match in *result*.

    Args:
        result: A completed ScanResult.
        entropy_map: Optional mapping of (path, line_number) -> entropy float.
        plausible_set: Optional set of (path, line_number) fingerprints deemed plausible.
    """
    entropy_map = entropy_map or {}
    plausible_set = plausible_set or set()
    scored = []
    for match in result.matches:
        key = (match.path, match.line_number)
        entropy = entropy_map.get(key, 0.0)
        plausible = key in plausible_set
        scored.append(_score_match(match, entropy=entropy, plausible=plausible))
    return ScoredResult(scored=scored, source_result=result)
