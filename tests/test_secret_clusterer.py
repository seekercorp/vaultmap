"""Tests for vaultmap.secret_clusterer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import pytest

from vaultmap.secret_clusterer import (
    ClusterReport,
    SecretCluster,
    _cluster_key,
    build_cluster_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _FakeMatch:
    path: str
    pattern_name: str
    line_number: int = 1
    value: str = "secret"
    severity: str = "high"


def _make_result(matches):
    class _R:
        pass
    r = _R()
    r.matches = matches
    return r


# ---------------------------------------------------------------------------
# SecretCluster
# ---------------------------------------------------------------------------

def test_cluster_count():
    m1 = _FakeMatch(path="src/app.py", pattern_name="aws_key")
    m2 = _FakeMatch(path="src/app.py", pattern_name="aws_key")
    cluster = SecretCluster(pattern_name="aws_key", directory="src", matches=[m1, m2])
    assert cluster.count == 2


def test_cluster_files_deduplicated():
    m1 = _FakeMatch(path="src/app.py", pattern_name="aws_key")
    m2 = _FakeMatch(path="src/app.py", pattern_name="aws_key")
    m3 = _FakeMatch(path="src/utils.py", pattern_name="aws_key")
    cluster = SecretCluster(pattern_name="aws_key", directory="src", matches=[m1, m2, m3])
    assert sorted(cluster.files) == ["src/app.py", "src/utils.py"]


def test_cluster_to_dict_keys():
    cluster = SecretCluster(pattern_name="github_token", directory="config", matches=[])
    d = cluster.to_dict()
    assert set(d.keys()) == {"pattern_name", "directory", "match_count", "files"}


# ---------------------------------------------------------------------------
# _cluster_key
# ---------------------------------------------------------------------------

def test_cluster_key_uses_parent_dir():
    m = _FakeMatch(path="src/auth/secrets.py", pattern_name="private_key")
    key = _cluster_key(m)
    assert key[1].endswith("src/auth") or key[1].endswith("src\\auth")
    assert key[0] == "private_key"


# ---------------------------------------------------------------------------
# build_cluster_report
# ---------------------------------------------------------------------------

def test_build_cluster_report_empty():
    report = build_cluster_report(_make_result([]))
    assert report.clusters == []
    assert report.total_matches == 0
    assert report.hotspot is None


def test_build_cluster_report_groups_by_pattern_and_dir():
    matches = [
        _FakeMatch(path="src/app.py", pattern_name="aws_key"),
        _FakeMatch(path="src/utils.py", pattern_name="aws_key"),
        _FakeMatch(path="config/env.py", pattern_name="aws_key"),
    ]
    report = build_cluster_report(_make_result(matches))
    assert len(report.clusters) == 2
    assert report.total_matches == 3


def test_build_cluster_report_hotspot_is_largest():
    matches = [
        _FakeMatch(path="src/a.py", pattern_name="aws_key"),
        _FakeMatch(path="src/b.py", pattern_name="aws_key"),
        _FakeMatch(path="config/c.py", pattern_name="github_token"),
    ]
    report = build_cluster_report(_make_result(matches))
    assert report.hotspot is not None
    assert report.hotspot.pattern_name == "aws_key"
    assert report.hotspot.count == 2


def test_build_cluster_report_to_dict_structure():
    matches = [_FakeMatch(path="src/app.py", pattern_name="aws_key")]
    report = build_cluster_report(_make_result(matches))
    d = report.to_dict()
    assert d["total_matches"] == 1
    assert d["cluster_count"] == 1
    assert isinstance(d["clusters"], list)
