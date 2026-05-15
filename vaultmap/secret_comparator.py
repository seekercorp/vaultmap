"""Compare two scan results and produce a structured comparison report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any

from vaultmap.scanner import ScanResult, Match
from vaultmap.baseline import _fingerprint


@dataclass
class ComparedMatch:
    match: Match
    status: str  # 'new' | 'resolved' | 'persisted'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "path": self.match.path,
            "line": self.match.line,
            "pattern": self.match.pattern_name,
            "severity": self.match.severity,
            "value": self.match.value,
        }


@dataclass
class ComparisonReport:
    new: List[ComparedMatch] = field(default_factory=list)
    resolved: List[ComparedMatch] = field(default_factory=list)
    persisted: List[ComparedMatch] = field(default_factory=list)

    @property
    def has_new(self) -> bool:
        return len(self.new) > 0

    @property
    def has_resolved(self) -> bool:
        return len(self.resolved) > 0

    @property
    def total(self) -> int:
        return len(self.new) + len(self.resolved) + len(self.persisted)

    def summary(self) -> Dict[str, int]:
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "persisted": len(self.persisted),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "new": [m.to_dict() for m in self.new],
            "resolved": [m.to_dict() for m in self.resolved],
            "persisted": [m.to_dict() for m in self.persisted],
        }


def compare_results(baseline: ScanResult, current: ScanResult) -> ComparisonReport:
    """Compare *baseline* against *current* and categorise every match."""
    baseline_fps: Dict[str, Match] = {
        _fingerprint(m): m for m in baseline.matches
    }
    current_fps: Dict[str, Match] = {
        _fingerprint(m): m for m in current.matches
    }

    report = ComparisonReport()

    for fp, match in current_fps.items():
        if fp in baseline_fps:
            report.persisted.append(ComparedMatch(match=match, status="persisted"))
        else:
            report.new.append(ComparedMatch(match=match, status="new"))

    for fp, match in baseline_fps.items():
        if fp not in current_fps:
            report.resolved.append(ComparedMatch(match=match, status="resolved"))

    return report
