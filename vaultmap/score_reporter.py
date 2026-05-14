"""Reporter for composite secret scores."""
from __future__ import annotations

import json
from typing import TextIO
import sys

from vaultmap.secret_scorer import ScoredResult


def _bar(score: int, width: int = 20) -> str:
    filled = int(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def print_score_text_report(
    scored_result: ScoredResult,
    out: TextIO = sys.stdout,
    top: int = 20,
) -> None:
    """Print a human-readable ranked list of scored matches."""
    items = scored_result.top(top)
    if not items:
        out.write("No scored findings.\n")
        return

    out.write(f"Top {len(items)} scored findings\n")
    out.write("=" * 60 + "\n")
    for i, s in enumerate(items, 1):
        label = _label(s.score)
        bar = _bar(s.score)
        out.write(
            f"{i:>3}. [{label:<8}] {bar} {s.score:>3}/100\n"
            f"      {s.match.path}:{s.match.line_number} "
            f"pattern={s.match.pattern_name}\n"
        )
        parts = ", ".join(f"{k}={v}" for k, v in s.breakdown.items())
        out.write(f"      breakdown: {parts}\n")
    out.write("\n")


def print_score_json_report(
    scored_result: ScoredResult,
    out: TextIO = sys.stdout,
    top: int = 20,
) -> None:
    """Print a JSON array of the top scored matches."""
    items = [s.to_dict() for s in scored_result.top(top)]
    json.dump({"scored_findings": items, "total": len(scored_result.scored)}, out, indent=2)
    out.write("\n")
