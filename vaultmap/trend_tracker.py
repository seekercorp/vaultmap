"""Track finding counts across scans to surface trends over time."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_TREND_FILE = Path(".vaultmap") / "trends.json"


@dataclass
class TrendEntry:
    timestamp: str
    total_findings: int
    by_severity: Dict[str, int]
    scanned_files: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "scanned_files": self.scanned_files,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TrendEntry":
        return cls(
            timestamp=d["timestamp"],
            total_findings=d["total_findings"],
            by_severity=d.get("by_severity", {}),
            scanned_files=d.get("scanned_files", 0),
        )


@dataclass
class TrendReport:
    entries: List[TrendEntry] = field(default_factory=list)

    @property
    def latest(self) -> Optional[TrendEntry]:
        return self.entries[-1] if self.entries else None

    @property
    def previous(self) -> Optional[TrendEntry]:
        return self.entries[-2] if len(self.entries) >= 2 else None

    def delta(self) -> Optional[int]:
        """Return change in total findings vs previous scan, or None."""
        if self.latest is None or self.previous is None:
            return None
        return self.latest.total_findings - self.previous.total_findings

    def trend_label(self) -> str:
        d = self.delta()
        if d is None:
            return "no prior data"
        if d > 0:
            return f"\u2191 +{d} since last scan"
        if d < 0:
            return f"\u2193 {d} since last scan"
        return "\u2192 no change since last scan"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_entry(
    total_findings: int,
    by_severity: Dict[str, int],
    scanned_files: int,
    trend_file: Path = _DEFAULT_TREND_FILE,
) -> TrendEntry:
    """Append a new entry to the trend log and return it."""
    trend_file.parent.mkdir(parents=True, exist_ok=True)
    entries = _load_entries(trend_file)
    entry = TrendEntry(
        timestamp=_utcnow(),
        total_findings=total_findings,
        by_severity=by_severity,
        scanned_files=scanned_files,
    )
    entries.append(entry)
    trend_file.write_text(
        json.dumps([e.to_dict() for e in entries], indent=2), encoding="utf-8"
    )
    return entry


def load_trend_report(trend_file: Path = _DEFAULT_TREND_FILE) -> TrendReport:
    return TrendReport(entries=_load_entries(trend_file))


def _load_entries(trend_file: Path) -> List[TrendEntry]:
    if not trend_file.exists():
        return []
    try:
        data = json.loads(trend_file.read_text(encoding="utf-8"))
        return [TrendEntry.from_dict(d) for d in data]
    except (json.JSONDecodeError, KeyError):
        return []
