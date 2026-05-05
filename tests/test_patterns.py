"""Tests for credential pattern definitions."""

import pytest
from vaultmap.patterns import PATTERNS, get_patterns_by_severity, CredentialPattern


def test_patterns_list_not_empty():
    assert len(PATTERNS) > 0


def test_all_patterns_have_required_fields():
    for p in PATTERNS:
        assert isinstance(p, CredentialPattern)
        assert p.name
        assert p.pattern
        assert p.severity in ("high", "medium", "low")
        assert p.description


def test_aws_access_key_matches():
    aws_pattern = next(p for p in PATTERNS if p.name == "aws_access_key")
    assert aws_pattern.pattern.search("AKIAIOSFODNN7EXAMPLE")
    assert not aws_pattern.pattern.search("not_an_aws_key")


def test_github_token_matches():
    gh_pattern = next(p for p in PATTERNS if p.name == "github_token")
    assert gh_pattern.pattern.search("ghp_" + "A" * 36)
    assert not gh_pattern.pattern.search("ghp_short")


def test_private_key_header_matches():
    pk_pattern = next(p for p in PATTERNS if p.name == "private_key_header")
    assert pk_pattern.pattern.search("-----BEGIN RSA PRIVATE KEY-----")
    assert pk_pattern.pattern.search("-----BEGIN PRIVATE KEY-----")
    assert not pk_pattern.pattern.search("-----BEGIN CERTIFICATE-----")


def test_jwt_token_matches():
    jwt_pattern = next(p for p in PATTERNS if p.name == "jwt_token")
    sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123XYZ"
    assert jwt_pattern.pattern.search(sample)


def test_get_patterns_by_severity_high():
    high = get_patterns_by_severity("high")
    assert all(p.severity == "high" for p in high)
    assert len(high) > 0


def test_get_patterns_by_severity_unknown_returns_empty():
    result = get_patterns_by_severity("critical")
    assert result == []
