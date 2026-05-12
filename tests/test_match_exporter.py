"""Tests for vaultmap.match_exporter."""

from __future__ import annotations

import csv
import io
import json

import pytest

from vaultmap.match_exporter import export_csv, export_ndjson, export_to_string
from vaultmap.scanner import Match, ScanResult


def _make_match(path="src/app.py", line=10, pattern_id="aws_key", severity="critical", value="AKIA1234"):
    return Match(
        path=path,
        line=line,
        pattern_id=pattern_id,
        severity=severity,
        value=value,
    )


def _make_result(matches=None):
    return ScanResult(
        scanned_files=1,
        matches=matches or [],
    )


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def test_export_csv_header_present():
    buf = io.StringIO()
    export_csv(_make_result(), buf)
    buf.seek(0)
    reader = csv.DictReader(buf)
    assert set(reader.fieldnames) >= {"path", "line", "pattern_id", "severity", "value"}


def test_export_csv_returns_row_count():
    result = _make_result([_make_match(), _make_match(line=20)])
    buf = io.StringIO()
    count = export_csv(result, buf)
    assert count == 2


def test_export_csv_values_correct():
    match = _make_match(path="config.py", line=5, value="secret123")
    buf = io.StringIO()
    export_csv(_make_result([match]), buf)
    buf.seek(0)
    rows = list(csv.DictReader(buf))
    assert rows[0]["path"] == "config.py"
    assert rows[0]["line"] == "5"
    assert rows[0]["value"] == "secret123"


def test_export_csv_empty_result_only_header():
    buf = io.StringIO()
    count = export_csv(_make_result([]), buf)
    assert count == 0
    buf.seek(0)
    lines = buf.read().splitlines()
    assert len(lines) == 1  # header only


# ---------------------------------------------------------------------------
# NDJSON export
# ---------------------------------------------------------------------------

def test_export_ndjson_returns_line_count():
    result = _make_result([_make_match(), _make_match(line=99)])
    buf = io.StringIO()
    count = export_ndjson(result, buf)
    assert count == 2


def test_export_ndjson_each_line_valid_json():
    result = _make_result([_make_match(), _make_match(path="other.py", line=3)])
    buf = io.StringIO()
    export_ndjson(result, buf)
    lines = [l for l in buf.getvalue().splitlines() if l]
    for line in lines:
        obj = json.loads(line)
        assert "pattern_id" in obj


# ---------------------------------------------------------------------------
# export_to_string
# ---------------------------------------------------------------------------

def test_export_to_string_csv():
    result = _make_result([_make_match()])
    output = export_to_string(result, fmt="csv")
    assert "aws_key" in output
    assert "path" in output  # header


def test_export_to_string_ndjson():
    result = _make_result([_make_match()])
    output = export_to_string(result, fmt="ndjson")
    obj = json.loads(output.strip())
    assert obj["severity"] == "critical"


def test_export_to_string_unknown_format_raises():
    with pytest.raises(ValueError, match="Unknown export format"):
        export_to_string(_make_result(), fmt="xml")  # type: ignore[arg-type]
