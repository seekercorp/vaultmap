"""File and directory scanner for vaultmap."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List

from vaultmap.patterns import CredentialPattern, get_patterns_by_severity
from vaultmap.suppression import build_suppressed_lines_for_file, filter_suppressed

_BINARY_CHUNK = 8192
_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json",
    ".toml", ".cfg", ".ini", ".sh", ".bash", ".zsh", ".rb",
    ".go", ".java", ".kt", ".cs", ".php", ".tf", ".hcl",
    ".txt", ".md", ".xml", ".properties",
}


@dataclass
class Match:
    file: str
    line_number: int
    line: str
    pattern_name: str
    severity: str
    matched_value: str


@dataclass
class ScanResult:
    scanned_files: int = 0
    matches: List[Match] = field(default_factory=list)


def has_findings(result: ScanResult) -> bool:
    return bool(result.matches)


def by_severity(result: ScanResult) -> dict[str, list[Match]]:
    out: dict[str, list[Match]] = {}
    for m in result.matches:
        out.setdefault(m.severity, []).append(m)
    return out


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(_BINARY_CHUNK)
        return b"\x00" in chunk
    except OSError:
        return True


def _iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in _TEXT_EXTENSIONS and not _is_binary(p):
                yield p


def scan_file(
    path: Path,
    patterns: list[CredentialPattern] | None = None,
    inline_suppress: bool = True,
) -> list[Match]:
    """Scan a single file and return a list of Match objects.

    Parameters
    ----------
    path:
        File to scan.
    patterns:
        Credential patterns to apply.  Defaults to all patterns.
    inline_suppress:
        When *True* (default), lines annotated with ``# vaultmap: ignore``
        or enclosed in ignore-start/end blocks are skipped.
    """
    if patterns is None:
        patterns = get_patterns_by_severity()

    try:
        source = path.read_text(errors="replace")
    except OSError:
        return []

    suppressed = (
        build_suppressed_lines(source)
        if inline_suppress
        else frozenset()
    )

    matches: list[Match] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if lineno in suppressed:
            continue
        for pat in patterns:
            for m in pat.regex.finditer(line):
                matches.append(
                    Match(
                        file=str(path),
                        line_number=lineno,
                        line=line.rstrip(),
                        pattern_name=pat.name,
                        severity=pat.severity,
                        matched_value=m.group(0),
                    )
                )
    return matches


def scan_directory(
    root: Path,
    patterns: list[CredentialPattern] | None = None,
    inline_suppress: bool = True,
) -> ScanResult:
    """Recursively scan *root* and return a ScanResult."""
    result = ScanResult()
    for file_path in _iter_files(root):
        result.scanned_files += 1
        result.matches.extend(
            scan_file(file_path, patterns=patterns, inline_suppress=inline_suppress)
        )
    return result


# Local import placed here to avoid circular dependency when suppression
# module imports nothing from scanner.
from vaultmap.suppression import build_suppressed_lines  # noqa: E402
