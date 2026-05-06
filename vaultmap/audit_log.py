"""Audit log: record scan events to a structured JSONL file."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vaultmap.scanner import ScanResult
from vaultmap.git_history import GitScanResult

AUDIT_LOG_ENV = "VAULTMAP_AUDIT_LOG"
_DEFAULT_LOG = Path("vaultmap-audit.jsonl")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_path(override: Optional[str] = None) -> Optional[Path]:
    """Return the configured log path, or None if logging is disabled."""
    raw = override or os.environ.get(AUDIT_LOG_ENV)
    if raw is None:
        return None
    return Path(raw)


def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def log_scan(result: ScanResult, *, log_file: Optional[str] = None) -> None:
    """Append a filesystem scan event to the audit log."""
    path = _log_path(log_file)
    if path is None:
        return
    record = {
        "event": "scan",
        "timestamp": _utcnow(),
        "scanned_files": result.scanned_files,
        "total_matches": sum(len(m) for m in result.matches.values()),
        "files_with_findings": list(result.matches.keys()),
    }
    _append(path, record)


def log_git_scan(result: GitScanResult, *, log_file: Optional[str] = None) -> None:
    """Append a git-history scan event to the audit log."""
    path = _log_path(log_file)
    if path is None:
        return
    from vaultmap.git_history import total_matches
    record = {
        "event": "git_scan",
        "timestamp": _utcnow(),
        "commits_scanned": len(result.commit_matches),
        "total_matches": total_matches(result),
        "commits_with_findings": [
            cm.commit_hash for cm in result.commit_matches if cm.matches
        ],
    }
    _append(path, record)


def load_audit_log(log_file: Optional[str] = None) -> list[dict]:
    """Return all records from the audit log as a list of dicts."""
    path = _log_path(log_file)
    if path is None or not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
