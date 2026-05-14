"""Tests for vaultmap.secret_tagger."""

from __future__ import annotations

import pytest

from vaultmap.scanner import Match
from vaultmap.secret_tagger import (
    TaggedMatch,
    tag_match,
    tag_result,
    tags_summary,
    _tags_for_match,
)
from vaultmap.scanner import ScanResult


def _make_match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    path: str = "config.py",
    line_number: int = 10,
    severity: str = "high",
) -> Match:
    return Match(
        path=path,
        line_number=line_number,
        pattern_name=pattern_name,
        value=value,
        severity=severity,
    )


def _make_result(matches: list[Match]) -> ScanResult:
    return ScanResult(path=".", matches=matches, files_scanned=1)


class TestTagsForMatch:
    def test_aws_pattern_gets_cloud_tag(self):
        m = _make_match(pattern_name="aws_access_key")
        tags = _tags_for_match(m)
        assert "cloud:aws" in tags

    def test_github_token_gets_vcs_tag(self):
        m = _make_match(pattern_name="github_token", value="ghp_" + "A" * 36)
        tags = _tags_for_match(m)
        assert "vcs:github" in tags

    def test_private_key_gets_crypto_tag(self):
        m = _make_match(pattern_name="private_key", value="-----BEGIN RSA PRIVATE KEY-----")
        tags = _tags_for_match(m)
        assert "crypto:private-key" in tags

    def test_multiline_value_gets_format_tag(self):
        m = _make_match(value="line1\nline2")
        tags = _tags_for_match(m)
        assert "format:multiline" in tags

    def test_high_entropy_value_gets_entropy_tag(self):
        value = "aB3$xZ9!qR2@mN7#pL5^wK8&vJ4%uH6*"
        m = _make_match(value=value)
        tags = _tags_for_match(m)
        assert "entropy:high" in tags

    def test_short_simple_value_no_entropy_tag(self):
        m = _make_match(value="abc")
        tags = _tags_for_match(m)
        assert "entropy:high" not in tags

    def test_tags_are_sorted_and_unique(self):
        m = _make_match(pattern_name="aws_api_key", value="AKIAIOSFODNN7EXAMPLE")
        tags = _tags_for_match(m)
        assert tags == sorted(set(tags))

    def test_unknown_pattern_no_tags(self):
        m = _make_match(pattern_name="unknown_xyz", value="short")
        tags = _tags_for_match(m)
        assert tags == []


class TestTagMatch:
    def test_returns_tagged_match_instance(self):
        m = _make_match()
        tm = tag_match(m)
        assert isinstance(tm, TaggedMatch)
        assert tm.match is m

    def test_to_dict_contains_required_keys(self):
        m = _make_match()
        d = tag_match(m).to_dict()
        assert {"path", "line", "pattern", "tags"}.issubset(d.keys())


class TestTagResult:
    def test_tag_result_returns_one_per_match(self):
        matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_" + "A" * 36)]
        result = _make_result(matches)
        tagged = tag_result(result)
        assert len(tagged) == 2

    def test_tag_result_empty_matches(self):
        result = _make_result([])
        assert tag_result(result) == []


class TestTagsSummary:
    def test_summary_counts_tags(self):
        m1 = _make_match(pattern_name="aws_access_key")
        m2 = _make_match(pattern_name="aws_secret_key")
        tagged = [tag_match(m1), tag_match(m2)]
        summary = tags_summary(tagged)
        assert summary.get("cloud:aws", 0) == 2

    def test_summary_empty_list(self):
        assert tags_summary([]) == {}

    def test_summary_is_sorted(self):
        m1 = _make_match(pattern_name="github_token", value="ghp_" + "A" * 36)
        m2 = _make_match(pattern_name="aws_access_key")
        summary = tags_summary([tag_match(m1), tag_match(m2)])
        assert list(summary.keys()) == sorted(summary.keys())
