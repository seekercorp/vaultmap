"""Tests for vaultmap.entropy module."""
import pytest

from vaultmap.entropy import (
    EntropyMatch,
    THRESHOLD_BASE64,
    THRESHOLD_HEX,
    _shannon,
    _tokens_for_charset,
    high_entropy_matches,
)


def test_shannon_empty_string_returns_zero():
    assert _shannon("") == 0.0


def test_shannon_uniform_string_low_entropy():
    # All same characters → entropy = 0
    assert _shannon("aaaaaaaaaa") == 0.0


def test_shannon_high_entropy_random_like():
    token = "aB3xQz9mLpWvRtYuIoEqNsDfGhJkCb2"
    assert _shannon(token) > 4.0


def test_tokens_for_charset_extracts_runs():
    text = "prefix ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij suffix"
    tokens = _tokens_for_charset(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    assert len(tokens) >= 1
    assert all(len(t) >= 20 for t in tokens)


def test_tokens_for_charset_short_run_ignored():
    text = "short ABCDE end"
    tokens = _tokens_for_charset(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert tokens == []


def test_high_entropy_matches_detects_base64_secret():
    # Simulate a high-entropy base64-like token (e.g. an API key)
    line = 'api_key = "aB3xQz9mLpWvRtYuIoEqNsDfGhJkCb2XwZyMnPeAoVuTsRiQlKjHgFd"'
    matches = high_entropy_matches(line)
    assert len(matches) >= 1
    assert all(isinstance(m, EntropyMatch) for m in matches)
    assert matches[0].charset == "base64"
    assert matches[0].entropy >= THRESHOLD_BASE64


def test_high_entropy_matches_clean_line_returns_empty():
    line = "x = 1  # just a normal assignment"
    assert high_entropy_matches(line) == []


def test_high_entropy_matches_no_duplicate_tokens():
    line = 'tok = "aB3xQz9mLpWvRtYuIoEqNsDfGhJkCb2XwZyMnPeAoVuTsRiQlKjHgFd"'
    matches = high_entropy_matches(line)
    tokens = [m.token for m in matches]
    assert len(tokens) == len(set(tokens))


def test_entropy_match_is_named_tuple():
    m = EntropyMatch(token="abc", entropy=3.5, charset="hex")
    assert m.token == "abc"
    assert m.entropy == 3.5
    assert m.charset == "hex"
