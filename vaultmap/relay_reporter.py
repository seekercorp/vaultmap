"""relay_reporter.py – human-readable and JSON output for relay reports."""
from __future__ import annotations

import json
from vaultmap.secret_relay import RelayReport

_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"


def _c(code: str, text: str, colour: bool) -> str:
    return f"{code}{text}{_RESET}" if colour else text


def print_relay_text_report(report: RelayReport, *, colour: bool = True) -> None:
    if not report.records:
        print("No findings were relayed.")
        return
    print(f"Relay summary: {report.sent} sent, {report.failed} failed\n")
    for rec in report.records:
        status = (
            _c(_GREEN, f"OK {rec.status_code}", colour)
            if rec.success
            else _c(_RED, f"FAIL {rec.error or rec.status_code}", colour)
        )
        print(f"  [{status}] {rec.path}:{rec.line}  ({rec.pattern})")


def print_relay_json_report(report: RelayReport) -> None:
    out = {
        "sent": report.sent,
        "failed": report.failed,
        "records": [r.to_dict() for r in report.records],
    }
    print(json.dumps(out, indent=2))
