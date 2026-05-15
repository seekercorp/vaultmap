"""Snapshot module: captures and compares point-in-time scan states."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultmap.scanner import Match, ScanResult


@dataclass
class SnapshotEntry:
    path: str
    pattern_name: str
    line_number: int
    value: str
    severity: str
    captured_at: float

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "pattern_name": self.pattern_name,
            "line_number": self.line_number,
            "value": self.value,
            "severity": self.severity,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SnapshotEntry":
        return cls(
            path=data["path"],
            pattern_name=data["pattern_name"],
            line_number=data["line_number"],
            value=data["value"],
            severity=data["severity"],
            captured_at=data["captured_at"],
        )


@dataclass
class Snapshot:
    label: str
    created_at: float
    entries: List[SnapshotEntry] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_dict(self) -> Dict:
        return {
            "label": self.label,
            "created_at": self.created_at,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Snapshot":
        return cls(
            label=data["label"],
            created_at=data["created_at"],
            entries=[SnapshotEntry.from_dict(e) for e in data.get("entries", [])],
        )


def _utcnow() -> float:
    return time.time()


def capture_snapshot(result: ScanResult, label: str) -> Snapshot:
    """Build a Snapshot from a ScanResult."""
    entries = [
        SnapshotEntry(
            path=m.path,
            pattern_name=m.pattern_name,
            line_number=m.line_number,
            value=m.value,
            severity=m.severity,
            captured_at=_utcnow(),
        )
        for m in result.matches
    ]
    return Snapshot(label=label, created_at=_utcnow(), entries=entries)


def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot.to_dict(), indent=2))


def load_snapshot(path: Path) -> Optional[Snapshot]:
    if not path.exists():
        return None
    return Snapshot.from_dict(json.loads(path.read_text()))


def diff_snapshots(before: Snapshot, after: Snapshot) -> Dict:
    """Return sets of added/removed entry fingerprints between two snapshots."""
    def _fp(e: SnapshotEntry) -> str:
        return f"{e.path}:{e.line_number}:{e.pattern_name}:{e.value}"

    before_fps = {_fp(e) for e in before.entries}
    after_fps = {_fp(e) for e in after.entries}
    return {
        "added": after_fps - before_fps,
        "removed": before_fps - after_fps,
        "unchanged": before_fps & after_fps,
    }
