"""Baseline management for vaultmap.

Allows saving and loading a set of known findings so that subsequent
scans only report *new* secrets that were not present in the baseline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, List, Set

from vaultmap.scanner import Match


def _fingerprint(match: Match) -> str:
    """Return a stable hash that uniquely identifies a finding."""
    raw = f"{match.file_path}:{match.line_number}:{match.pattern_id}:{match.matched_value}"
    return hashlib.sha256(raw.encode()).hexdigest()


def save_baseline(matches: Iterable[Match], path: str | Path) -> None:
    """Persist a collection of matches as a JSON baseline file.

    Args:
        matches: Iterable of Match objects representing current findings.
        path:    Destination file path for the baseline JSON.
    """
    fingerprints = sorted({_fingerprint(m) for m in matches})
    payload = {"version": 1, "fingerprints": fingerprints}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(path: str | Path) -> Set[str]:
    """Load a previously saved baseline and return its fingerprint set.

    Returns an empty set if the file does not exist.

    Raises:
        ValueError: If the file exists but contains invalid JSON or an
            unrecognised baseline version.
    """
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file '{path}' contains invalid JSON: {exc}") from exc
    version = data.get("version")
    if version != 1:
        raise ValueError(
            f"Unsupported baseline version '{version}' in '{path}'. "
            "Expected version 1."
        )
    return set(data.get("fingerprints", []))


def filter_new_matches(matches: Iterable[Match], baseline: Set[str]) -> List[Match]:
    """Return only matches whose fingerprint is absent from *baseline*."""
    return [m for m in matches if _fingerprint(m) not in baseline]


def is_new(match: Match, baseline: Set[str]) -> bool:
    """Return True when *match* is not covered by *baseline*."""
    return _fingerprint(match) not in baseline
