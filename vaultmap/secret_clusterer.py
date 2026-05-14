"""Cluster secrets by similarity — groups matches that share the same
pattern name and file directory, helping identify co-located credential
leak hotspots across a codebase."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence

from vaultmap.scanner import Match, ScanResult


@dataclass
class SecretCluster:
    """A group of matches sharing a pattern and parent directory."""

    pattern_name: str
    directory: str
    matches: List[Match] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.matches)

    @property
    def files(self) -> List[str]:
        seen: dict = {}
        for m in self.matches:
            seen[m.path] = True
        return list(seen.keys())

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "directory": self.directory,
            "match_count": self.count,
            "files": self.files,
        }


@dataclass
class ClusterReport:
    clusters: List[SecretCluster] = field(default_factory=list)

    @property
    def total_matches(self) -> int:
        return sum(c.count for c in self.clusters)

    @property
    def hotspot(self) -> SecretCluster | None:
        """Return the cluster with the most matches, or None if empty."""
        if not self.clusters:
            return None
        return max(self.clusters, key=lambda c: c.count)

    def to_dict(self) -> dict:
        return {
            "total_matches": self.total_matches,
            "cluster_count": len(self.clusters),
            "clusters": [c.to_dict() for c in self.clusters],
        }


def _cluster_key(match: Match) -> tuple:
    directory = str(Path(match.path).parent)
    return (match.pattern_name, directory)


def build_cluster_report(result: ScanResult) -> ClusterReport:
    """Group all matches in *result* into clusters by (pattern, directory)."""
    buckets: Dict[tuple, SecretCluster] = {}
    for match in result.matches:
        key = _cluster_key(match)
        if key not in buckets:
            pattern_name, directory = key
            buckets[key] = SecretCluster(
                pattern_name=pattern_name, directory=directory
            )
        buckets[key].matches.append(match)
    clusters = sorted(
        buckets.values(), key=lambda c: c.count, reverse=True
    )
    return ClusterReport(clusters=clusters)
