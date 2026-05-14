"""secret_profiler.py — Builds a profile summary for each unique secret pattern found
in a ScanResult, aggregating occurrence counts, affected files, severity, and entropy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultmap.scanner import ScanResult, Match


@dataclass
class PatternProfile:
    """Aggregated statistics for a single credential pattern."""

    pattern_name: str
    severity: str
    occurrences: int = 0
    affected_files: List[str] = field(default_factory=list)
    avg_entropy: Optional[float] = None
    sample_line: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "occurrences": self.occurrences,
            "unique_files": len(set(self.affected_files)),
            "avg_entropy": round(self.avg_entropy, 4) if self.avg_entropy is not None else None,
            "sample_line": self.sample_line,
        }


@dataclass
class ProfileReport:
    """Collection of per-pattern profiles derived from a ScanResult."""

    profiles: Dict[str, PatternProfile] = field(default_factory=dict)

    def top_by_occurrences(self, n: int = 5) -> List[PatternProfile]:
        """Return the n patterns with the highest occurrence counts."""
        return sorted(self.profiles.values(), key=lambda p: p.occurrences, reverse=True)[:n]

    def by_severity(self, severity: str) -> List[PatternProfile]:
        """Return all profiles matching the given severity level."""
        return [p for p in self.profiles.values() if p.severity == severity]

    def to_dict(self) -> dict:
        return {name: profile.to_dict() for name, profile in self.profiles.items()}


def build_profile_report(result: ScanResult) -> ProfileReport:
    """Build a ProfileReport by aggregating matches in *result* by pattern name."""
    report = ProfileReport()
    entropy_sums: Dict[str, float] = {}
    entropy_counts: Dict[str, int] = {}

    for match in result.matches:
        name = match.pattern_name
        if name not in report.profiles:
            report.profiles[name] = PatternProfile(
                pattern_name=name,
                severity=match.severity,
                sample_line=match.line_number,
            )
            entropy_sums[name] = 0.0
            entropy_counts[name] = 0

        profile = report.profiles[name]
        profile.occurrences += 1
        profile.affected_files.append(match.path)

        if match.entropy is not None:
            entropy_sums[name] += match.entropy
            entropy_counts[name] += 1

    for name, profile in report.profiles.items():
        if entropy_counts[name] > 0:
            profile.avg_entropy = entropy_sums[name] / entropy_counts[name]

    return report
