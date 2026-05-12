"""Groups matches by pattern type, file, or severity for aggregated reporting."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from vaultmap.scanner import Match, ScanResult


@dataclass
class MatchGroup:
    """A named collection of matches sharing a common grouping key."""

    key: str
    matches: List[Match] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.matches)

    @property
    def files(self) -> List[str]:
        return sorted({m.path for m in self.matches})

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "count": self.count,
            "files": self.files,
        }


@dataclass
class GroupedReport:
    """Container for all groups produced by a grouping strategy."""

    strategy: str
    groups: List[MatchGroup] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(g.count for g in self.groups)

    def get(self, key: str) -> MatchGroup | None:
        for g in self.groups:
            if g.key == key:
                return g
        return None

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "total": self.total,
            "groups": [g.to_dict() for g in self.groups],
        }


def _build_groups(matches: Sequence[Match], key_fn) -> Dict[str, List[Match]]:
    buckets: Dict[str, List[Match]] = defaultdict(list)
    for m in matches:
        buckets[key_fn(m)].append(m)
    return buckets


def group_by_pattern(result: ScanResult) -> GroupedReport:
    """Group matches by their pattern name."""
    buckets = _build_groups(result.matches, lambda m: m.pattern_name)
    groups = [MatchGroup(key=k, matches=v) for k, v in sorted(buckets.items())]
    return GroupedReport(strategy="pattern", groups=groups)


def group_by_file(result: ScanResult) -> GroupedReport:
    """Group matches by the file path they were found in."""
    buckets = _build_groups(result.matches, lambda m: m.path)
    groups = [MatchGroup(key=k, matches=v) for k, v in sorted(buckets.items())]
    return GroupedReport(strategy="file", groups=groups)


def group_by_severity(result: ScanResult) -> GroupedReport:
    """Group matches by severity level (high → medium → low)."""
    order = {"high": 0, "medium": 1, "low": 2}
    buckets = _build_groups(result.matches, lambda m: m.severity)
    groups = [
        MatchGroup(key=k, matches=v)
        for k, v in sorted(buckets.items(), key=lambda kv: order.get(kv[0], 99))
    ]
    return GroupedReport(strategy="severity", groups=groups)
