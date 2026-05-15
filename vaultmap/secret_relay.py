"""secret_relay.py – forward scan findings to external webhook endpoints."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from vaultmap.scanner import Match, ScanResult


@dataclass
class RelayConfig:
    url: str
    headers: dict = field(default_factory=dict)
    timeout: int = 10
    include_value: bool = False


@dataclass
class RelayRecord:
    path: str
    line: int
    pattern: str
    severity: str
    value: Optional[str]
    status_code: Optional[int] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "line": self.line,
            "pattern": self.pattern,
            "severity": self.severity,
            "value": self.value,
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass
class RelayReport:
    records: List[RelayRecord] = field(default_factory=list)

    @property
    def sent(self) -> int:
        return sum(1 for r in self.records if r.success)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.records if not r.success)


def _build_payload(match: Match, include_value: bool) -> bytes:
    data = {
        "path": match.path,
        "line": match.line,
        "pattern": match.pattern,
        "severity": match.severity,
    }
    if include_value:
        data["value"] = match.value
    return json.dumps(data).encode()


def relay_match(match: Match, config: RelayConfig) -> RelayRecord:
    record = RelayRecord(
        path=match.path,
        line=match.line,
        pattern=match.pattern,
        severity=match.severity,
        value=match.value if config.include_value else None,
    )
    payload = _build_payload(match, config.include_value)
    headers = {"Content-Type": "application/json", **config.headers}
    req = urllib.request.Request(config.url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            record.status_code = resp.status
    except urllib.error.HTTPError as exc:
        record.status_code = exc.code
        record.error = str(exc)
    except Exception as exc:  # noqa: BLE001
        record.error = str(exc)
    return record


def relay_result(result: ScanResult, config: RelayConfig) -> RelayReport:
    report = RelayReport()
    for match in result.matches:
        report.records.append(relay_match(match, config))
    return report


def relay_matches(matches: Iterable[Match], config: RelayConfig) -> RelayReport:
    report = RelayReport()
    for match in matches:
        report.records.append(relay_match(match, config))
    return report
