"""secret_masker.py — Mask matched secret values before display or export.

Provides structured masking with configurable strategies: full, partial, and
hash-based. Wraps existing Match objects without mutating them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Literal

from vaultmap.scanner import Match, ScanResult

MaskStrategy = Literal["full", "partial", "hash"]

_FULL_MASK = "***REDACTED***"
_PARTIAL_VISIBLE = 4  # chars shown at start and end for partial masking
_MIN_LEN_FOR_PARTIAL = 10


@dataclass(frozen=True)
class MaskedMatch:
    original: Match
    masked_value: str
    strategy: MaskStrategy

    def to_dict(self) -> dict:
        return {
            "path": self.original.path,
            "line": self.original.line,
            "pattern": self.original.pattern,
            "severity": self.original.severity,
            "masked_value": self.masked_value,
            "strategy": self.strategy,
        }


@dataclass
class MaskedResult:
    matches: List[MaskedMatch]
    files_scanned: int

    def __len__(self) -> int:
        return len(self.matches)

    def has_findings(self) -> bool:
        return bool(self.matches)


def _mask_full(value: str) -> str:  # noqa: ARG001
    return _FULL_MASK


def _mask_partial(value: str) -> str:
    if len(value) < _MIN_LEN_FOR_PARTIAL:
        return _FULL_MASK
    head = value[:_PARTIAL_VISIBLE]
    tail = value[-_PARTIAL_VISIBLE:]
    stars = "*" * max(4, len(value) - _PARTIAL_VISIBLE * 2)
    return f"{head}{stars}{tail}"


def _mask_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"sha256:{digest}"


_STRATEGIES = {
    "full": _mask_full,
    "partial": _mask_partial,
    "hash": _mask_hash,
}


def mask_match(match: Match, strategy: MaskStrategy = "partial") -> MaskedMatch:
    """Return a MaskedMatch wrapping *match* with its value obscured."""
    fn = _STRATEGIES.get(strategy, _mask_partial)
    return MaskedMatch(
        original=match,
        masked_value=fn(match.value),
        strategy=strategy,
    )


def mask_result(result: ScanResult, strategy: MaskStrategy = "partial") -> MaskedResult:
    """Return a MaskedResult with every match in *result* masked."""
    masked = [mask_match(m, strategy) for m in result.matches]
    return MaskedResult(matches=masked, files_scanned=result.files_scanned)
