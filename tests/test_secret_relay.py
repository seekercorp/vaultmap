"""Tests for vaultmap.secret_relay."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from dataclasses import dataclass
from typing import Optional

import pytest

from vaultmap.secret_relay import (
    RelayConfig,
    RelayRecord,
    RelayReport,
    _build_payload,
    relay_match,
    relay_matches,
    relay_result,
)


@dataclass
class _FakeMatch:
    path: str = "src/app.py"
    line: int = 10
    pattern: str = "aws_access_key"
    severity: str = "critical"
    value: str = "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _StubServer:
    """Tiny HTTP server that records the last request body and returns 200."""

    def __init__(self) -> None:
        self.last_body: Optional[bytes] = None
        self._server: Optional[HTTPServer] = None

    def start(self) -> str:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                parent.last_body = self.rfile.read(length)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                pass  # suppress output

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        port = self._server.server_address[1]
        t = threading.Thread(target=self._server.handle_request, daemon=True)
        t.start()
        return f"http://127.0.0.1:{port}/hook"

    def stop(self) -> None:
        if self._server:
            self._server.server_close()


# ---------------------------------------------------------------------------
# unit tests (no network)
# ---------------------------------------------------------------------------

def test_build_payload_excludes_value_by_default():
    m = _FakeMatch()
    data = json.loads(_build_payload(m, include_value=False))
    assert "value" not in data
    assert data["pattern"] == "aws_access_key"


def test_build_payload_includes_value_when_requested():
    m = _FakeMatch()
    data = json.loads(_build_payload(m, include_value=True))
    assert data["value"] == "AKIAIOSFODNN7EXAMPLE"


def test_relay_record_success_true_on_2xx():
    rec = RelayRecord(path="f", line=1, pattern="p", severity="high", value=None, status_code=201)
    assert rec.success is True


def test_relay_record_success_false_on_error():
    rec = RelayRecord(path="f", line=1, pattern="p", severity="high", value=None, error="timeout")
    assert rec.success is False


def test_relay_report_counts():
    ok = RelayRecord(path="a", line=1, pattern="p", severity="high", value=None, status_code=200)
    fail = RelayRecord(path="b", line=2, pattern="p", severity="high", value=None, error="err")
    report = RelayReport(records=[ok, fail])
    assert report.sent == 1
    assert report.failed == 1


def test_relay_match_network_error_captured():
    m = _FakeMatch()
    cfg = RelayConfig(url="http://127.0.0.1:1/nope", timeout=1)
    rec = relay_match(m, cfg)
    assert rec.success is False
    assert rec.error is not None


# ---------------------------------------------------------------------------
# integration test with stub HTTP server
# ---------------------------------------------------------------------------

def test_relay_match_sends_correct_payload():
    srv = _StubServer()
    url = srv.start()
    m = _FakeMatch()
    cfg = RelayConfig(url=url, include_value=True)
    rec = relay_match(m, cfg)
    srv.stop()
    assert rec.success
    body = json.loads(srv.last_body)
    assert body["path"] == m.path
    assert body["value"] == m.value


def test_relay_matches_returns_report_for_each():
    matches = [_FakeMatch(line=i) for i in range(3)]
    cfg = RelayConfig(url="http://127.0.0.1:1/nope", timeout=1)
    report = relay_matches(matches, cfg)
    assert len(report.records) == 3
