"""match_diff.py – compare two ScanResult snapshots and surface new/resolved findings."""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, List

from vaultmap.baseline import _fingerprint
from vaultmap.scanner import Match, ScanResult


@dataclass(frozen=True)
class DiffReport:
    """Holds the delta between a previous and current scan."""

    new_matches: List[Match]
    resolved_matches: List[Match]
    persisted_count: int

    @property
    def has_new(self) -> bool:
        return len(self.new_matches) > 0

    @property
    def has_resolved(self) -> bool:
        return len(self.resolved_matches) > 0

    def summary(self) -> str:
        return (
            f"new={len(self.new_matches)} "
            f"resolved={len(self.resolved_matches)} "
            f"persisted={self.persisted_count}"
        )


def _fingerprint_set(matches: List[Match]) -> FrozenSet[str]:
    return frozenset(_fingerprint(m) for m in matches)


def diff_results(previous: ScanResult, current: ScanResult) -> DiffReport:
    """Return a DiffReport describing changes between two ScanResult objects."""
    prev_fps = _fingerprint_set(previous.matches)
    curr_fps = _fingerprint_set(current.matches)

    new_fps = curr_fps - prev_fps
    resolved_fps = prev_fps - curr_fps
    persisted_count = len(prev_fps & curr_fps)

    new_matches = [m for m in current.matches if _fingerprint(m) in new_fps]
    resolved_matches = [m for m in previous.matches if _fingerprint(m) in resolved_fps]

    return DiffReport(
        new_matches=new_matches,
        resolved_matches=resolved_matches,
        persisted_count=persisted_count,
    )


def diff_summary_lines(report: DiffReport) -> List[str]:
    """Return human-readable lines describing the diff."""
    lines: List[str] = []
    if report.has_new:
        lines.append(f"  [+] {len(report.new_matches)} new finding(s):")
        for m in report.new_matches:
            lines.append(f"      {m.path}:{m.line_number}  [{m.pattern_name}]")
    if report.has_resolved:
        lines.append(f"  [-] {len(report.resolved_matches)} resolved finding(s):")
        for m in report.resolved_matches:
            lines.append(f"      {m.path}:{m.line_number}  [{m.pattern_name}]")
    if not report.has_new and not report.has_resolved:
        lines.append("  No changes since last scan.")
    lines.append(f"  Persisted: {report.persisted_count}")
    return lines
