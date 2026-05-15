"""Reporter for snapshot captures and diffs."""
from __future__ import annotations

import json
from typing import Dict

from vaultmap.secret_snapshot import Snapshot, diff_snapshots

_COLORS = {"added": "\033[91m", "removed": "\033[92m", "reset": "\033[0m", "bold": "\033[1m"}


def _c(key: str, text: str, color: bool) -> str:
    return f"{_COLORS[key]}{text}{_COLORS['reset']}" if color else text


def print_snapshot_text_report(snapshot: Snapshot, *, color: bool = True) -> None:
    header = _c("bold", f"Snapshot: {snapshot.label}", color)
    print(header)
    print(f"  Captured at : {snapshot.created_at:.0f}")
    print(f"  Total entries: {snapshot.count}")
    if not snapshot.entries:
        print("  (no findings)")
        return
    for e in snapshot.entries:
        print(f"  [{e.severity.upper()}] {e.path}:{e.line_number}  {e.pattern_name}")


def print_snapshot_json_report(snapshot: Snapshot) -> None:
    print(json.dumps(snapshot.to_dict(), indent=2))


def print_snapshot_diff_text_report(
    before: Snapshot,
    after: Snapshot,
    *,
    color: bool = True,
) -> None:
    diff = diff_snapshots(before, after)
    added = diff["added"]
    removed = diff["removed"]
    unchanged = diff["unchanged"]

    print(_c("bold", f"Snapshot diff: '{before.label}' -> '{after.label}'", color))
    print(f"  Unchanged : {len(unchanged)}")
    print(f"  Added     : {len(added)}")
    print(f"  Removed   : {len(removed)}")

    if added:
        print(_c("added", "  + New findings:", color))
        for fp in sorted(added):
            print(f"      {fp}")

    if removed:
        print(_c("removed", "  - Resolved findings:", color))
        for fp in sorted(removed):
            print(f"      {fp}")

    if not added and not removed:
        print("  No changes between snapshots.")


def print_snapshot_diff_json_report(before: Snapshot, after: Snapshot) -> None:
    diff = diff_snapshots(before, after)
    output: Dict = {
        "before": before.label,
        "after": after.label,
        "added": sorted(diff["added"]),
        "removed": sorted(diff["removed"]),
        "unchanged_count": len(diff["unchanged"]),
    }
    print(json.dumps(output, indent=2))
