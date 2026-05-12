"""Tests for vaultmap.watchdog."""
from __future__ import annotations

import time
from pathlib import Path
from typing import List, Tuple

import pytest

from vaultmap.watchdog import WatchState, _collect_paths, watch


# ---------------------------------------------------------------------------
# WatchState
# ---------------------------------------------------------------------------

def test_watch_state_is_changed_new_file(tmp_path: Path) -> None:
    f = tmp_path / "secret.py"
    f.write_text("x = 1")
    state = WatchState(root=tmp_path)
    assert state.is_changed(f)  # never snapshotted


def test_watch_state_not_changed_after_snapshot(tmp_path: Path) -> None:
    f = tmp_path / "secret.py"
    f.write_text("x = 1")
    state = WatchState(root=tmp_path)
    state.snapshot_mtime(f)
    assert not state.is_changed(f)


def test_watch_state_changed_after_write(tmp_path: Path) -> None:
    f = tmp_path / "secret.py"
    f.write_text("x = 1")
    state = WatchState(root=tmp_path)
    state.snapshot_mtime(f)
    time.sleep(0.05)
    f.write_text("x = 2")
    # touch ensures mtime differs on fast filesystems
    import os
    os.utime(f, (time.time() + 1, time.time() + 1))
    assert state.is_changed(f)


def test_watch_state_missing_file_returns_false(tmp_path: Path) -> None:
    state = WatchState(root=tmp_path)
    assert not state.is_changed(tmp_path / "ghost.py")


# ---------------------------------------------------------------------------
# _collect_paths
# ---------------------------------------------------------------------------

def test_collect_paths_finds_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("pass")
    (tmp_path / "b.txt").write_text("hello")
    paths = _collect_paths(tmp_path)
    assert len(paths) == 2


def test_collect_paths_extension_filter(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("pass")
    (tmp_path / "b.txt").write_text("hello")
    paths = _collect_paths(tmp_path, extensions={".py"})
    assert all(p.suffix == ".py" for p in paths)
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# watch()
# ---------------------------------------------------------------------------

def test_watch_calls_on_finding_for_new_secret(tmp_path: Path) -> None:
    findings: List[Tuple[Path, list]] = []

    def on_finding(path, matches):
        findings.append((path, matches))

    secret_file = tmp_path / "creds.py"
    secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    watch(
        root=tmp_path,
        on_finding=on_finding,
        interval=0.0,
        max_iterations=1,
    )

    assert len(findings) == 1
    assert findings[0][0] == secret_file


def test_watch_no_finding_for_clean_file(tmp_path: Path) -> None:
    findings: list = []
    (tmp_path / "clean.py").write_text("x = 42")

    watch(
        root=tmp_path,
        on_finding=lambda p, m: findings.append((p, m)),
        interval=0.0,
        max_iterations=1,
    )

    assert findings == []


def test_watch_second_iteration_skips_unchanged(tmp_path: Path) -> None:
    findings: list = []
    secret_file = tmp_path / "creds.py"
    secret_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')

    watch(
        root=tmp_path,
        on_finding=lambda p, m: findings.append((p, m)),
        interval=0.0,
        max_iterations=2,
    )

    # File unchanged in 2nd iteration → on_finding called exactly once
    assert len(findings) == 1
