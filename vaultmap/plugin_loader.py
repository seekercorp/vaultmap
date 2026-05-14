"""Plugin loader — discovers and registers external vaultmap pattern plugins.

Plugins are Python packages that expose a ``vaultmap_patterns`` entry-point
group.  Each entry-point must be a callable that returns a list of
``CredentialPattern`` instances.
"""
from __future__ import annotations

import importlib.metadata
import logging
from typing import List

from vaultmap.patterns import CredentialPattern

log = logging.getLogger(__name__)

_ENTRY_POINT_GROUP = "vaultmap_patterns"


def _iter_entry_points(group: str):
    """Yield entry-points for *group*, compatible with Python 3.9+."""
    try:
        eps = importlib.metadata.entry_points(group=group)
    except TypeError:
        # Python 3.8 fallback
        eps = importlib.metadata.entry_points().get(group, [])
    yield from eps


def load_plugins() -> List[CredentialPattern]:
    """Return all ``CredentialPattern`` objects contributed by installed plugins.

    Errors in individual plugins are logged and skipped so that a broken
    plugin does not prevent the rest of vaultmap from running.
    """
    patterns: List[CredentialPattern] = []
    for ep in _iter_entry_points(_ENTRY_POINT_GROUP):
        try:
            factory = ep.load()
            contributed = factory()
            if not isinstance(contributed, list):
                raise TypeError(
                    f"Plugin '{ep.name}' must return a list, got {type(contributed)}"
                )
            for p in contributed:
                if not isinstance(p, CredentialPattern):
                    raise TypeError(
                        f"Plugin '{ep.name}' returned non-CredentialPattern: {type(p)}"
                    )
            patterns.extend(contributed)
            log.debug("Loaded %d pattern(s) from plugin '%s'", len(contributed), ep.name)
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to load plugin '%s': %s", ep.name, exc)
    return patterns


def list_plugins() -> List[str]:
    """Return the names of all registered plugin entry-points."""
    return [ep.name for ep in _iter_entry_points(_ENTRY_POINT_GROUP)]
