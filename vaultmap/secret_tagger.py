"""Assign human-readable tags to matches based on pattern name and value heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from vaultmap.scanner import Match, ScanResult

# Map pattern-name substrings to canonical tags
_PATTERN_TAG_MAP: list[tuple[str, str]] = [
    ("aws", "cloud:aws"),
    ("gcp", "cloud:gcp"),
    ("azure", "cloud:azure"),
    ("github", "vcs:github"),
    ("gitlab", "vcs:gitlab"),
    ("private_key", "crypto:private-key"),
    ("rsa", "crypto:rsa"),
    ("jwt", "auth:jwt"),
    ("password", "auth:password"),
    ("token", "auth:token"),
    ("api_key", "auth:api-key"),
    ("secret", "auth:secret"),
    ("database", "data:database"),
    ("slack", "comms:slack"),
    ("stripe", "payment:stripe"),
    ("twilio", "comms:twilio"),
]

_HIGH_ENTROPY_TAG = "entropy:high"
_MULTILINE_TAG = "format:multiline"


@dataclass
class TaggedMatch:
    match: Match
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.match.path,
            "line": self.match.line_number,
            "pattern": self.match.pattern_name,
            "tags": self.tags,
        }


def _tags_for_match(match: Match) -> list[str]:
    tags: list[str] = []
    name_lower = match.pattern_name.lower()
    for keyword, tag in _PATTERN_TAG_MAP:
        if keyword in name_lower:
            tags.append(tag)
    if "\n" in match.value:
        tags.append(_MULTILINE_TAG)
    if len(match.value) >= 32 and len(set(match.value)) > 16:
        tags.append(_HIGH_ENTROPY_TAG)
    return sorted(set(tags))


def tag_match(match: Match) -> TaggedMatch:
    """Return a TaggedMatch with auto-assigned tags."""
    return TaggedMatch(match=match, tags=_tags_for_match(match))


def tag_result(result: ScanResult) -> list[TaggedMatch]:
    """Tag every match in a ScanResult."""
    return [tag_match(m) for m in result.matches]


def tags_summary(tagged: Sequence[TaggedMatch]) -> dict[str, int]:
    """Return a frequency map of tags across all tagged matches."""
    counts: dict[str, int] = {}
    for tm in tagged:
        for tag in tm.tags:
            counts[tag] = counts.get(tag, 0) + 1
    return dict(sorted(counts.items()))


def filter_by_tag(tagged: Sequence[TaggedMatch], tag: str) -> list[TaggedMatch]:
    """Return only the TaggedMatches that include the given tag.

    Args:
        tagged: A sequence of TaggedMatch instances to filter.
        tag: The exact tag string to match against each item's tag list.

    Returns:
        A list of TaggedMatch objects whose tags contain ``tag``.
    """
    return [tm for tm in tagged if tag in tm.tags]
