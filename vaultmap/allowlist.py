"""Allowlist support for suppressing known-safe findings."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class AllowlistEntry:
    """A single allowlist rule."""

    pattern: str
    reason: str
    paths: List[str] = field(default_factory=list)

    def matches_value(self, value: str) -> bool:
        """Return True if *value* matches this entry's pattern."""
        return bool(re.search(self.pattern, value))

    def matches_path(self, path: str) -> bool:
        """Return True if *path* is covered by this entry (empty list = all paths)."""
        if not self.paths:
            return True
        return any(re.search(p, path) for p in self.paths)


@dataclass
class Allowlist:
    """Collection of allowlist entries loaded from a config file."""

    entries: List[AllowlistEntry] = field(default_factory=list)

    def is_allowed(self, value: str, path: str = "") -> bool:
        """Return True if *value* at *path* is suppressed by any entry."""
        return any(
            e.matches_value(value) and e.matches_path(path)
            for e in self.entries
        )

    @classmethod
    def from_file(cls, config_path: Path) -> "Allowlist":
        """Load an allowlist from a JSON file.

        Expected format::

            [
              {
                "pattern": "AKIAIOSFODNN7EXAMPLE",
                "reason": "test fixture",
                "paths": ["tests/"]
              }
            ]
        """
        if not config_path.exists():
            return cls()
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        entries = [
            AllowlistEntry(
                pattern=item["pattern"],
                reason=item.get("reason", ""),
                paths=item.get("paths", []),
            )
            for item in raw
        ]
        return cls(entries=entries)

    @classmethod
    def empty(cls) -> "Allowlist":
        """Return an allowlist that suppresses nothing."""
        return cls()


DEFAULT_ALLOWLIST_PATH = Path(".vaultmap-allowlist.json")


def load_allowlist(path: Optional[Path] = None) -> Allowlist:
    """Load allowlist from *path*, falling back to the default location."""
    target = path if path is not None else DEFAULT_ALLOWLIST_PATH
    return Allowlist.from_file(target)
