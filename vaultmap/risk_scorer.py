"""Risk scoring module — assigns a numeric risk score to scan results
based on severity, entropy, match count, and file sensitivity."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from vaultmap.scanner import Match, ScanResult

# Severity weights
_SEVERITY_SCORE: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 1,
}

# Paths whose presence multiplies the base score
_SENSITIVE_PATH_PATTERNS: list[str] = [
    ".env",
    "config",
    "secret",
    "credential",
    "password",
    "private",
    "key",
    "token",
]

_SENSITIVE_PATH_MULTIPLIER = 1.5
_ENTROPY_BONUS_PER_MATCH = 8


@dataclass(frozen=True)
class MatchRisk:
    match: Match
    base_score: int
    path_multiplier: float
    entropy_bonus: int

    @property
    def total(self) -> float:
        return (self.base_score + self.entropy_bonus) * self.path_multiplier


@dataclass(frozen=True)
class RiskReport:
    total_score: float
    match_risks: List[MatchRisk]
    risk_level: str

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in ("high", "critical")


def _path_multiplier(path: str) -> float:
    lower = Path(path).name.lower()
    for pattern in _SENSITIVE_PATH_PATTERNS:
        if pattern in lower:
            return _SENSITIVE_PATH_MULTIPLIER
    return 1.0


def score_match(match: Match) -> MatchRisk:
    base = _SEVERITY_SCORE.get(match.severity.lower(), 5)
    multiplier = _path_multiplier(match.path)
    entropy_bonus = _ENTROPY_BONUS_PER_MATCH if getattr(match, "from_entropy", False) else 0
    return MatchRisk(
        match=match,
        base_score=base,
        path_multiplier=multiplier,
        entropy_bonus=entropy_bonus,
    )


def _risk_level(score: float) -> str:
    if score >= 150:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def score_result(result: ScanResult) -> RiskReport:
    match_risks = [score_match(m) for m in result.matches]
    total = sum(mr.total for mr in match_risks)
    return RiskReport(
        total_score=round(total, 2),
        match_risks=match_risks,
        risk_level=_risk_level(total),
    )
