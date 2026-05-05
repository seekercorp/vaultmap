"""Scan git history for credential patterns."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from vaultmap.patterns import get_patterns_by_severity
from vaultmap.scanner import Match


@dataclass
class CommitMatch:
    commit_hash: str
    commit_message: str
    file_path: str
    matches: list[Match] = field(default_factory=list)


@dataclass
class GitScanResult:
    repo_path: str
    commit_matches: list[CommitMatch] = field(default_factory=list)
    commits_scanned: int = 0

    @property
    def has_findings(self) -> bool:
        return any(cm.matches for cm in self.commit_matches)

    @property
    def total_matches(self) -> int:
        return sum(len(cm.matches) for cm in self.commit_matches)


def _iter_commits(repo_path: Path, max_commits: int = 200) -> Iterator[tuple[str, str]]:
    """Yield (hash, subject) tuples for recent commits."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "log", f"--max-count={max_commits}",
         "--pretty=format:%H %s"],
        capture_output=True, text=True, check=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            yield parts[0], parts[1]


def _get_commit_diff(repo_path: Path, commit_hash: str) -> str:
    """Return the unified diff introduced by a single commit."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "show", "--unified=0", commit_hash],
        capture_output=True, text=True,
    )
    return result.stdout


def scan_git_history(
    repo_path: str | Path,
    severity_filter: str | None = None,
    max_commits: int = 200,
) -> GitScanResult:
    """Scan git history of *repo_path* for credential patterns."""
    repo_path = Path(repo_path)
    patterns = get_patterns_by_severity(severity_filter)
    result = GitScanResult(repo_path=str(repo_path))

    for commit_hash, commit_msg in _iter_commits(repo_path, max_commits):
        result.commits_scanned += 1
        diff = _get_commit_diff(repo_path, commit_hash)
        current_file = "<unknown>"
        matches: list[Match] = []

        for lineno, line in enumerate(diff.splitlines(), start=1):
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            content = line[1:]
            for pattern in patterns:
                for m in pattern.regex.finditer(content):
                    matches.append(Match(
                        file=current_file,
                        line_number=lineno,
                        line_content=content.strip(),
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        matched_value=m.group(),
                    ))

        if matches:
            result.commit_matches.append(
                CommitMatch(commit_hash=commit_hash, commit_message=commit_msg,
                            file_path=current_file, matches=matches)
            )

    return result
