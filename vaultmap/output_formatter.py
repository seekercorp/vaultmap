"""Output formatter for vaultmap scan results — supports SARIF export format."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from vaultmap.scanner import ScanResult, Match
from vaultmap.git_history import GitScanResult, CommitMatch

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
_TOOL_NAME = "vaultmap"
_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/example/vaultmap"


def _make_rule(pattern_id: str, name: str, severity: str) -> dict[str, Any]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(
        severity.lower(), "warning"
    )
    return {
        "id": pattern_id,
        "name": name,
        "shortDescription": {"text": f"Potential credential match: {name}"},
        "defaultConfiguration": {"level": level},
        "properties": {"severity": severity},
    }


def _make_result(rule_id: str, message: str, uri: str, line: int, snippet: str) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": line,
                        "snippet": {"text": snippet},
                    },
                }
            }
        ],
    }


def build_sarif(scan_result: ScanResult) -> dict[str, Any]:
    """Convert a filesystem ScanResult to a SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for match in scan_result.matches:
        rid = match.pattern_id
        if rid not in rules:
            rules[rid] = _make_rule(rid, match.pattern_name, match.severity)
        results.append(
            _make_result(
                rid,
                f"{match.pattern_name} detected",
                match.file_path,
                match.line_number,
                match.matched_text,
            )
        )

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def print_sarif_report(scan_result: ScanResult) -> None:
    """Print a SARIF-formatted report to stdout."""
    print(json.dumps(build_sarif(scan_result), indent=2))
