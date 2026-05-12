"""secret_age.py — Tracks how long secrets have been present in the codebase
by comparing current matches against a timestamped baseline record."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultmap.baseline import _fingerprint
from vaultmap.scanner import Match, ScanResult

_DEFAULT_AGE_FILE = Path(".vaultmap_age.json")


@dataclass
class AgedMatch:
    match: Match
    first_seen: float  # Unix timestamp
    age_days: float

    def is_stale(self, threshold_days: int = 30) -> bool:
        """Return True if the secret has been present longer than *threshold_days*."""
        return self.age_days >= threshold_days


@dataclass
class AgeReport:
    aged: List[AgedMatch] = field(default_factory=list)

    @property
    def stale(self) -> List[AgedMatch]:
        return [a for a in self.aged if a.is_stale()]

    def oldest(self) -> Optional[AgedMatch]:
        return max(self.aged, key=lambda a: a.age_days, default=None)


def _load_age_db(path: Path) -> Dict[str, float]:
    """Load fingerprint -> first_seen mapping from *path*."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_age_db(db: Dict[str, float], path: Path) -> None:
    path.write_text(json.dumps(db, indent=2), encoding="utf-8")


def update_and_build_report(
    result: ScanResult,
    age_file: Path = _DEFAULT_AGE_FILE,
    now: Optional[float] = None,
) -> AgeReport:
    """Update the persistent age database and return an :class:`AgeReport`.

    New fingerprints are recorded with the current timestamp; existing ones
    retain their original *first_seen* value.
    """
    now = now if now is not None else time.time()
    db = _load_age_db(age_file)

    aged_matches: List[AgedMatch] = []
    for match in result.matches:
        fp = _fingerprint(match)
        if fp not in db:
            db[fp] = now
        first_seen = db[fp]
        age_days = (now - first_seen) / 86_400
        aged_matches.append(AgedMatch(match=match, first_seen=first_seen, age_days=age_days))

    _save_age_db(db, age_file)
    return AgeReport(aged=aged_matches)
