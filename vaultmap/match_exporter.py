"""Export scan matches to CSV or NDJSON formats for downstream tooling."""

from __future__ import annotations

import csv
import io
import json
from typing import IO, Literal

from vaultmap.scanner import Match, ScanResult

_CSV_FIELDS = [
    "path",
    "line",
    "pattern_id",
    "severity",
    "value",
    "context",
]


def _match_to_dict(match: Match) -> dict:
    return {
        "path": match.path,
        "line": match.line,
        "pattern_id": match.pattern_id,
        "severity": match.severity,
        "value": match.value,
        "context": getattr(match, "context", ""),
    }


def export_csv(result: ScanResult, dest: IO[str]) -> int:
    """Write matches from *result* to *dest* as CSV.

    Returns the number of rows written (excluding the header).
    """
    writer = csv.DictWriter(dest, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    count = 0
    for match in result.matches:
        writer.writerow(_match_to_dict(match))
        count += 1
    return count


def export_ndjson(result: ScanResult, dest: IO[str]) -> int:
    """Write matches from *result* to *dest* as newline-delimited JSON.

    Returns the number of lines written.
    """
    count = 0
    for match in result.matches:
        dest.write(json.dumps(_match_to_dict(match), ensure_ascii=False))
        dest.write("\n")
        count += 1
    return count


def export_to_string(
    result: ScanResult,
    fmt: Literal["csv", "ndjson"] = "csv",
) -> str:
    """Return the exported content as a plain string."""
    buf = io.StringIO()
    if fmt == "csv":
        export_csv(result, buf)
    elif fmt == "ndjson":
        export_ndjson(result, buf)
    else:
        raise ValueError(f"Unknown export format: {fmt!r}")
    return buf.getvalue()
