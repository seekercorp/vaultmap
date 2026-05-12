"""Provides surrounding line context for matches found during scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

DEFAULT_CONTEXT_LINES = 2


@dataclass
class MatchContext:
    """Lines of source context surrounding a detected match."""

    path: str
    line_number: int
    before: List[str] = field(default_factory=list)
    matched: str = ""
    after: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "line_number": self.line_number,
            "before": self.before,
            "matched": self.matched,
            "after": self.after,
        }


def extract_context(
    path: str,
    line_number: int,
    lines: Optional[List[str]] = None,
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> MatchContext:
    """Return a MatchContext for *line_number* (1-based) inside *path*.

    If *lines* is supplied it is used directly (useful in tests / when the
    file has already been read).  Otherwise the file is read from disk.
    """
    if lines is None:
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return MatchContext(path=path, line_number=line_number)

    idx = line_number - 1  # convert to 0-based
    before_start = max(0, idx - context_lines)
    after_end = min(len(lines), idx + context_lines + 1)

    before = lines[before_start:idx]
    matched = lines[idx] if 0 <= idx < len(lines) else ""
    after = lines[idx + 1 : after_end]

    return MatchContext(
        path=path,
        line_number=line_number,
        before=before,
        matched=matched,
        after=after,
    )


def enrich_result_with_context(
    matches,
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> List[MatchContext]:
    """Return a list of MatchContext objects for every Match in *matches*."""
    contexts: List[MatchContext] = []
    # Cache file contents keyed by path to avoid repeated disk reads.
    file_cache: dict = {}
    for match in matches:
        if match.path not in file_cache:
            try:
                file_cache[match.path] = (
                    Path(match.path)
                    .read_text(encoding="utf-8", errors="replace")
                    .splitlines()
                )
            except OSError:
                file_cache[match.path] = []
        ctx = extract_context(
            path=match.path,
            line_number=match.line_number,
            lines=file_cache[match.path],
            context_lines=context_lines,
        )
        contexts.append(ctx)
    return contexts
