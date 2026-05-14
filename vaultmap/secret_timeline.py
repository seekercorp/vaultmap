"""secret_timeline.py — Builds a chronological timeline of when secrets first
appeared and last appeared across git history scan results."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultmap.git_history import CommitMatch, GitScanResult


@dataclass
class TimelineEntry:
    """Records the lifespan of a unique secret across commits."""

    pattern_name: str
    file_path: str
    first_seen_commit: str
    first_seen_date: str
    last_seen_commit: str
    last_seen_date: str
    occurrences: int = 0
    commits: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "file_path": self.file_path,
            "first_seen_commit": self.first_seen_commit,
            "first_seen_date": self.first_seen_date,
            "last_seen_commit": self.last_seen_commit,
            "last_seen_date": self.last_seen_date,
            "occurrences": self.occurrences,
            "commits": self.commits,
        }


@dataclass
class SecretTimeline:
    entries: List[TimelineEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    def longest_lived(self) -> Optional[TimelineEntry]:
        """Return the entry that has appeared in the most commits."""
        if not self.entries:
            return None
        return max(self.entries, key=lambda e: e.occurrences)

    def to_dict(self) -> dict:
        return {
            "total_unique_secrets": self.total,
            "entries": [e.to_dict() for e in self.entries],
        }


def _entry_key(match: CommitMatch) -> str:
    return f"{match.pattern_name}::{match.file_path}"


def build_timeline(result: GitScanResult) -> SecretTimeline:
    """Aggregate CommitMatch records into a SecretTimeline.

    Commits are assumed to be returned in reverse-chronological order
    (newest first), which is the default for ``git log``.
    """
    seen: Dict[str, TimelineEntry] = {}

    for commit_hash, date, matches in result.commits:
        for m in matches:
            key = _entry_key(m)
            if key not in seen:
                # First time we encounter this key it is the *most recent*
                # sighting (newest-first ordering).
                seen[key] = TimelineEntry(
                    pattern_name=m.pattern_name,
                    file_path=m.file_path,
                    first_seen_commit=commit_hash,
                    first_seen_date=date,
                    last_seen_commit=commit_hash,
                    last_seen_date=date,
                    occurrences=1,
                    commits=[commit_hash],
                )
            else:
                entry = seen[key]
                # Older commits push the "first seen" marker back in time.
                entry.first_seen_commit = commit_hash
                entry.first_seen_date = date
                entry.occurrences += 1
                if commit_hash not in entry.commits:
                    entry.commits.append(commit_hash)

    return SecretTimeline(entries=list(seen.values()))
