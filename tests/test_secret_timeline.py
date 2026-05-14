"""Tests for vaultmap.secret_timeline."""
import pytest

from vaultmap.git_history import CommitMatch, GitScanResult
from vaultmap.secret_timeline import (
    SecretTimeline,
    TimelineEntry,
    build_timeline,
)


def _commit_match(pattern: str, path: str, line: int = 1) -> CommitMatch:
    return CommitMatch(
        pattern_name=pattern,
        file_path=path,
        line_number=line,
        matched_value="FAKE_SECRET",
        severity="high",
    )


def _make_git_result(commits):
    """commits: list of (hash, date, [CommitMatch])"""
    return GitScanResult(commits=commits)


# ---------------------------------------------------------------------------
# TimelineEntry.to_dict
# ---------------------------------------------------------------------------

def test_timeline_entry_to_dict_keys():
    entry = TimelineEntry(
        pattern_name="aws_access_key",
        file_path="config.py",
        first_seen_commit="abc",
        first_seen_date="2024-01-01",
        last_seen_commit="def",
        last_seen_date="2024-06-01",
        occurrences=3,
        commits=["abc", "bcd", "def"],
    )
    d = entry.to_dict()
    assert d["pattern_name"] == "aws_access_key"
    assert d["occurrences"] == 3
    assert len(d["commits"]) == 3


# ---------------------------------------------------------------------------
# build_timeline — empty result
# ---------------------------------------------------------------------------

def test_build_timeline_empty_result():
    result = _make_git_result([])
    timeline = build_timeline(result)
    assert timeline.total == 0
    assert timeline.longest_lived() is None


# ---------------------------------------------------------------------------
# build_timeline — single commit, single match
# ---------------------------------------------------------------------------

def test_build_timeline_single_match():
    m = _commit_match("aws_access_key", "app/config.py")
    result = _make_git_result([("sha1", "2024-03-01", [m])])
    timeline = build_timeline(result)
    assert timeline.total == 1
    entry = timeline.entries[0]
    assert entry.pattern_name == "aws_access_key"
    assert entry.first_seen_commit == "sha1"
    assert entry.last_seen_commit == "sha1"
    assert entry.occurrences == 1


# ---------------------------------------------------------------------------
# build_timeline — same secret across multiple commits
# ---------------------------------------------------------------------------

def test_build_timeline_tracks_across_commits():
    m = _commit_match("github_token", "deploy.sh")
    # newest-first order
    result = _make_git_result([
        ("sha3", "2024-05-01", [m]),
        ("sha2", "2024-04-01", [m]),
        ("sha1", "2024-03-01", [m]),
    ])
    timeline = build_timeline(result)
    assert timeline.total == 1
    entry = timeline.entries[0]
    assert entry.occurrences == 3
    assert entry.last_seen_commit == "sha3"   # most recent
    assert entry.first_seen_commit == "sha1"  # oldest
    assert set(entry.commits) == {"sha1", "sha2", "sha3"}


# ---------------------------------------------------------------------------
# build_timeline — two distinct secrets
# ---------------------------------------------------------------------------

def test_build_timeline_distinct_secrets():
    m1 = _commit_match("aws_access_key", "config.py")
    m2 = _commit_match("private_key", "id_rsa")
    result = _make_git_result([("sha1", "2024-01-01", [m1, m2])])
    timeline = build_timeline(result)
    assert timeline.total == 2


# ---------------------------------------------------------------------------
# SecretTimeline.longest_lived
# ---------------------------------------------------------------------------

def test_longest_lived_returns_most_frequent():
    m1 = _commit_match("aws_access_key", "a.py")
    m2 = _commit_match("github_token", "b.py")
    result = _make_git_result([
        ("sha3", "2024-05-01", [m1]),
        ("sha2", "2024-04-01", [m1, m2]),
        ("sha1", "2024-03-01", [m1]),
    ])
    timeline = build_timeline(result)
    longest = timeline.longest_lived()
    assert longest is not None
    assert longest.pattern_name == "aws_access_key"
    assert longest.occurrences == 3


# ---------------------------------------------------------------------------
# SecretTimeline.to_dict
# ---------------------------------------------------------------------------

def test_timeline_to_dict_structure():
    m = _commit_match("aws_access_key", "config.py")
    result = _make_git_result([("sha1", "2024-01-01", [m])])
    d = build_timeline(result).to_dict()
    assert "total_unique_secrets" in d
    assert "entries" in d
    assert d["total_unique_secrets"] == 1
