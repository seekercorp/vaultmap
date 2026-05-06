"""Tests for vaultmap.output_formatter SARIF export."""
from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

import pytest

from vaultmap.output_formatter import build_sarif, print_sarif_report
from vaultmap.scanner import ScanResult


def _make_match(
    pattern_id="aws_access_key",
    pattern_name="AWS Access Key",
    severity="critical",
    file_path="src/config.py",
    line_number=42,
    matched_text="AKIAIOSFODNN7EXAMPLE",
):
    from vaultmap.scanner import Match

    return Match(
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        matched_text=matched_text,
    )


@pytest.fixture()
def result_with_findings():
    return ScanResult(
        matches=[_make_match(), _make_match(pattern_id="github_token", pattern_name="GitHub Token", severity="high", line_number=7)],
        scanned_files=3,
    )


@pytest.fixture()
def result_clean():
    return ScanResult(matches=[], scanned_files=5)


def test_sarif_schema_version(result_with_findings):
    doc = build_sarif(result_with_findings)
    assert doc["version"] == "2.1.0"
    assert "sarif" in doc["$schema"]


def test_sarif_has_single_run(result_with_findings):
    doc = build_sarif(result_with_findings)
    assert len(doc["runs"]) == 1


def test_sarif_tool_name(result_with_findings):
    doc = build_sarif(result_with_findings)
    assert doc["runs"][0]["tool"]["driver"]["name"] == "vaultmap"


def test_sarif_results_count(result_with_findings):
    doc = build_sarif(result_with_findings)
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_rules_deduplicated():
    """Two matches with the same pattern_id should produce one rule entry."""
    result = ScanResult(matches=[_make_match(), _make_match(line_number=99)], scanned_files=1)
    doc = build_sarif(result)
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_sarif_result_location(result_with_findings):
    doc = build_sarif(result_with_findings)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/config.py"
    assert loc["region"]["startLine"] == 42


def test_sarif_critical_maps_to_error(result_with_findings):
    doc = build_sarif(result_with_findings)
    rule = next(r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "aws_access_key")
    assert rule["defaultConfiguration"]["level"] == "error"


def test_sarif_clean_result_has_no_results(result_clean):
    doc = build_sarif(result_clean)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_print_sarif_report_outputs_valid_json(result_with_findings, capsys):
    print_sarif_report(result_with_findings)
    captured = capsys.readouterr().out
    parsed = json.loads(captured)
    assert "runs" in parsed
