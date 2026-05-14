"""Tests for vaultmap.plugin_loader."""
from __future__ import annotations

import importlib.metadata
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vaultmap.patterns import CredentialPattern
from vaultmap.plugin_loader import load_plugins, list_plugins


def _make_pattern(name: str = "test-plugin-pattern") -> CredentialPattern:
    return CredentialPattern(
        name=name,
        pattern=r"TEST_[A-Z0-9]{16}",
        severity="medium",
        description="A test pattern from a plugin",
    )


def _make_ep(ep_name: str, factory):
    ep = MagicMock(spec=importlib.metadata.EntryPoint)
    ep.name = ep_name
    ep.load.return_value = factory
    return ep


@patch("vaultmap.plugin_loader._iter_entry_points", return_value=[])
def test_load_plugins_no_plugins_returns_empty(mock_iter):
    result = load_plugins()
    assert result == []


@patch("vaultmap.plugin_loader._iter_entry_points")
def test_load_plugins_returns_contributed_patterns(mock_iter):
    pattern = _make_pattern()
    ep = _make_ep("my-plugin", lambda: [pattern])
    mock_iter.return_value = [ep]

    result = load_plugins()

    assert len(result) == 1
    assert result[0] is pattern


@patch("vaultmap.plugin_loader._iter_entry_points")
def test_load_plugins_skips_broken_plugin(mock_iter, caplog):
    good_pattern = _make_pattern("good")
    bad_ep = _make_ep("bad-plugin", MagicMock(side_effect=RuntimeError("boom")))
    good_ep = _make_ep("good-plugin", lambda: [good_pattern])
    mock_iter.return_value = [bad_ep, good_ep]

    import logging
    with caplog.at_level(logging.WARNING, logger="vaultmap.plugin_loader"):
        result = load_plugins()

    assert len(result) == 1
    assert result[0] is good_pattern
    assert "bad-plugin" in caplog.text


@patch("vaultmap.plugin_loader._iter_entry_points")
def test_load_plugins_rejects_non_list(mock_iter, caplog):
    ep = _make_ep("bad-type", lambda: "not-a-list")
    mock_iter.return_value = [ep]

    import logging
    with caplog.at_level(logging.WARNING, logger="vaultmap.plugin_loader"):
        result = load_plugins()

    assert result == []
    assert "bad-type" in caplog.text


@patch("vaultmap.plugin_loader._iter_entry_points")
def test_load_plugins_rejects_wrong_item_type(mock_iter, caplog):
    ep = _make_ep("bad-item", lambda: [SimpleNamespace(name="x")])
    mock_iter.return_value = [ep]

    import logging
    with caplog.at_level(logging.WARNING, logger="vaultmap.plugin_loader"):
        result = load_plugins()

    assert result == []


@patch("vaultmap.plugin_loader._iter_entry_points", return_value=[])
def test_list_plugins_empty(mock_iter):
    assert list_plugins() == []


@patch("vaultmap.plugin_loader._iter_entry_points")
def test_list_plugins_returns_names(mock_iter):
    mock_iter.return_value = [
        _make_ep("plugin-a", lambda: []),
        _make_ep("plugin-b", lambda: []),
    ]
    names = list_plugins()
    assert names == ["plugin-a", "plugin-b"]
