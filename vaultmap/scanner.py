"""Core file scanning logic for detecting credential patterns."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from vaultmap.patterns import PATTERNS, CredentialPattern


@dataclass
class Match:
    file_path: str
    line_number: int
    line_content: str
    pattern: CredentialPattern
    matched_text: str


@dataclass
class ScanResult:
    scanned_files: int = 0
    matches: list[Match] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.matches) > 0

    def by_severity(self, severity: str) -> list[Match]:
        return [m for m in self.matches if m.pattern.severity == severity]


DEFAULT_IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
DEFAULT_IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".bin", ".exe", ".zip"}


def _iter_files(root: Path, ignore_dirs: set[str], ignore_extensions: set[str]) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            if any(part in ignore_dirs for part in path.parts):
                continue
            if path.suffix.lower() in ignore_extensions:
                continue
            yield path


def scan_file(file_path: Path) -> list[Match]:
    """Scan a single file for credential patterns."""
    matches: list[Match] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return matches

    for lineno, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            for m in pattern.pattern.finditer(line):
                matches.append(
                    Match(
                        file_path=str(file_path),
                        line_number=lineno,
                        line_content=line.strip(),
                        pattern=pattern,
                        matched_text=m.group(0),
                    )
                )
    return matches


def scan_directory(
    root: str | Path,
    ignore_dirs: set[str] | None = None,
    ignore_extensions: set[str] | None = None,
) -> ScanResult:
    """Recursively scan a directory and return aggregated results."""
    root = Path(root)
    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    ignore_extensions = ignore_extensions or DEFAULT_IGNORE_EXTENSIONS

    result = ScanResult()
    for file_path in _iter_files(root, ignore_dirs, ignore_extensions):
        result.scanned_files += 1
        result.matches.extend(scan_file(file_path))
    return result
