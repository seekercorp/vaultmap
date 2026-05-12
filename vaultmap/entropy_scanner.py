"""Bridge between entropy detection and the main scanner data model."""
from __future__ import annotations

from pathlib import Path
from typing import List

from vaultmap.entropy import high_entropy_matches
from vaultmap.scanner import Match


def scan_file_for_entropy(path: Path) -> List[Match]:
    """Return entropy-based *Match* objects for every suspicious token in *path*.

    Binary files and files that cannot be decoded as UTF-8 are silently skipped.
    """
    matches: List[Match] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (UnicodeDecodeError, OSError):
        return matches

    for lineno, line in enumerate(lines, start=1):
        for em in high_entropy_matches(line):
            pattern_name = f"high-entropy-{em.charset}"
            matches.append(
                Match(
                    path=str(path),
                    line_number=lineno,
                    line=line,
                    pattern_name=pattern_name,
                    severity="medium",
                    value=em.token,
                )
            )
    return matches


def scan_lines_for_entropy(path: str, lines: List[str]) -> List[Match]:
    """Scan an in-memory list of *lines* (e.g. from a git diff) for entropy.

    *path* is used only for populating Match.path.
    """
    matches: List[Match] = []
    for lineno, line in enumerate(lines, start=1):
        for em in high_entropy_matches(line):
            pattern_name = f"high-entropy-{em.charset}"
            matches.append(
                Match(
                    path=path,
                    line_number=lineno,
                    line=line,
                    pattern_name=pattern_name,
                    severity="medium",
                    value=em.token,
                )
            )
    return matches
