"""Severity breakdown report: aggregates match counts and risk by severity level."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from vaultmap.scanner import Match, ScanResult
from vaultmap.patterns import get_patterns_by_severity


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class SeverityBucket:
    severity: str
    count: int = 0
    files: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "count": self.count,
            "unique_files": sorted(set(self.files)),
            "unique_patterns": sorted(set(self.patterns)),
        }


@dataclass
class SeverityReport:
    buckets: Dict[str, SeverityBucket] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(b.count for b in self.buckets.values())

    def bucket(self, severity: str) -> SeverityBucket:
        return self.buckets.get(severity, SeverityBucket(severity=severity))

    def ordered(self) -> List[SeverityBucket]:
        """Return buckets in canonical severity order, highest first."""
        return [
            self.buckets[s]
            for s in _SEVERITY_ORDER
            if s in self.buckets
        ]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "breakdown": [b.to_dict() for b in self.ordered()],
        }


def build_severity_report(result: ScanResult) -> SeverityReport:
    """Build a SeverityReport from a completed ScanResult."""
    buckets: Dict[str, SeverityBucket] = {}

    for match in result.matches:
        sev = (match.severity or "info").lower()
        if sev not in buckets:
            buckets[sev] = SeverityBucket(severity=sev)
        bucket = buckets[sev]
        bucket.count += 1
        bucket.files.append(match.path)
        bucket.patterns.append(match.pattern_name)

    return SeverityReport(buckets=buckets)


def print_severity_report(result: ScanResult, use_color: bool = True) -> None:
    """Print a human-readable severity breakdown to stdout."""
    report = build_severity_report(result)

    _COLOR = {
        "critical": "\033[1;31m",
        "high": "\033[31m",
        "medium": "\033[33m",
        "low": "\033[34m",
        "info": "\033[36m",
    }
    _RESET = "\033[0m"

    print(f"\nSeverity Breakdown  (total: {report.total})")
    print("-" * 40)
    for bucket in report.ordered():
        color = _COLOR.get(bucket.severity, "") if use_color else ""
        reset = _RESET if use_color else ""
        label = bucket.severity.upper().ljust(8)
        print(
            f"  {color}{label}{reset}  {bucket.count:>4} match(es)  "
            f"across {len(set(bucket.files))} file(s)"
        )
    if not report.buckets:
        print("  No findings.")
    print()
