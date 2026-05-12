"""Path-based ignore rules for vaultmap.

Supports glob patterns (via fnmatch) to exclude files or directories
from scanning, similar to .gitignore semantics.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List

DEFAULT_IGNORE_PATTERNS: List[str] = [
    ".git/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/*.pyo",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "*.egg-info/**",
    "dist/**",
    "build/**",
]


@dataclass
class IgnoreRules:
    """Collection of glob patterns used to skip paths during scanning."""

    patterns: List[str] = field(default_factory=list)
    use_defaults: bool = True

    def _effective_patterns(self) -> List[str]:
        base = list(DEFAULT_IGNORE_PATTERNS) if self.use_defaults else []
        return base + self.patterns

    def is_ignored(self, path: str | os.PathLike) -> bool:
        """Return True if *path* matches any ignore pattern."""
        normalised = Path(path).as_posix()
        for pattern in self._effective_patterns():
            if fnmatch.fnmatch(normalised, pattern):
                return True
            # Also match basename alone so patterns like '*.pyc' work on
            # full paths such as 'src/utils/helper.pyc'.
            if fnmatch.fnmatch(os.path.basename(normalised), pattern):
                return True
        return False

    def filter(self, paths: Iterable[str | os.PathLike]) -> List[str]:
        """Return only those paths that are *not* ignored."""
        return [str(p) for p in paths if not self.is_ignored(p)]


def load_ignore_file(ignore_file: str | os.PathLike) -> List[str]:
    """Read a plain-text ignore file (one glob per line, # comments allowed)."""
    patterns: List[str] = []
    try:
        with open(ignore_file, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except FileNotFoundError:
        pass
    return patterns


def build_ignore_rules(
    extra_patterns: Iterable[str] = (),
    ignore_file: str | os.PathLike | None = None,
    use_defaults: bool = True,
) -> IgnoreRules:
    """Convenience factory that merges file-based and inline patterns."""
    patterns = list(extra_patterns)
    if ignore_file is not None:
        patterns = load_ignore_file(ignore_file) + patterns
    return IgnoreRules(patterns=patterns, use_defaults=use_defaults)
