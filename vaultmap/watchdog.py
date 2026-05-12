"""File-system watch mode: re-scan files on change and report new findings."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from vaultmap.baseline import filter_new_matches, load_baseline, save_baseline
from vaultmap.scanner import Match, ScanResult, scan_file


@dataclass
class WatchState:
    """Tracks mtimes and a running baseline for the watch session."""
    root: Path
    baseline_path: Optional[Path] = None
    _mtimes: Dict[str, float] = field(default_factory=dict)
    _seen_fingerprints: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.baseline_path and self.baseline_path.exists():
            self._seen_fingerprints = load_baseline(self.baseline_path)

    def snapshot_mtime(self, path: Path) -> None:
        self._mtimes[str(path)] = path.stat().st_mtime

    def is_changed(self, path: Path) -> bool:
        try:
            return path.stat().st_mtime != self._mtimes.get(str(path), -1.0)
        except FileNotFoundError:
            return False

    def record_matches(self, matches: list[Match]) -> None:
        from vaultmap.baseline import _fingerprint
        for m in matches:
            self._seen_fingerprints.add(_fingerprint(m))
        if self.baseline_path:
            save_baseline(self._seen_fingerprints, self.baseline_path)


def _collect_paths(root: Path, extensions: Optional[Set[str]] = None) -> list[Path]:
    paths = []
    for p in root.rglob("*"):
        if p.is_file():
            if extensions is None or p.suffix in extensions:
                paths.append(p)
    return paths


def watch(
    root: Path,
    on_finding: Callable[[Path, list[Match]], None],
    interval: float = 2.0,
    baseline_path: Optional[Path] = None,
    extensions: Optional[Set[str]] = None,
    max_iterations: Optional[int] = None,
) -> None:
    """Poll *root* every *interval* seconds and call *on_finding* for new matches."""
    state = WatchState(root=root, baseline_path=baseline_path)
    iteration = 0
    while True:
        for path in _collect_paths(root, extensions):
            if state.is_changed(path):
                result: ScanResult = scan_file(path)
                new_matches = filter_new_matches(result.matches, state._seen_fingerprints)
                if new_matches:
                    on_finding(path, new_matches)
                    state.record_matches(new_matches)
                state.snapshot_mtime(path)
        iteration += 1
        if max_iterations is not None and iteration >= max_iterations:
            break
        time.sleep(interval)
