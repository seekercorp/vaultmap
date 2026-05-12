"""Tests for vaultmap.path_classifier."""

import pytest

from vaultmap.path_classifier import (
    ClassifiedPath,
    PathSensitivity,
    classify_path,
    classify_paths,
)


# ---------------------------------------------------------------------------
# Individual classify_path cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    ".env",
    ".env.production",
    "backend/.env",
    "secrets.yaml",
    "config/secrets.yml",
    "credentials",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "server.pem",
    "keystore.p12",
    "cert.pfx",
])
def test_critical_paths(path: str) -> None:
    result = classify_path(path)
    assert result.sensitivity == PathSensitivity.CRITICAL, f"Expected CRITICAL for {path!r}, got {result.sensitivity}"


@pytest.mark.parametrize("path", [
    "config.yaml",
    "app.yml",
    "settings.toml",
    "database.ini",
    "nginx.conf",
    "docker-compose.yml",
    "Dockerfile",
    "Dockerfile.prod",
])
def test_high_paths(path: str) -> None:
    result = classify_path(path)
    assert result.sensitivity == PathSensitivity.HIGH, f"Expected HIGH for {path!r}, got {result.sensitivity}"


@pytest.mark.parametrize("path", [
    "app.py",
    "server.js",
    "main.go",
    "deploy.sh",
    "infra/main.tf",
    "variables.tfvars",
])
def test_medium_paths(path: str) -> None:
    result = classify_path(path)
    assert result.sensitivity == PathSensitivity.MEDIUM, f"Expected MEDIUM for {path!r}, got {result.sensitivity}"


@pytest.mark.parametrize("path", [
    "tests/test_scanner.py",
    "docs/guide.md",
    "README.md",
    "CHANGELOG.rst",
    "notes.txt",
])
def test_low_paths(path: str) -> None:
    result = classify_path(path)
    assert result.sensitivity == PathSensitivity.LOW, f"Expected LOW for {path!r}, got {result.sensitivity}"


def test_unknown_extension_returns_low() -> None:
    result = classify_path("somefile.xyz")
    assert result.sensitivity == PathSensitivity.LOW
    assert result.reason == "unrecognised file type"


def test_classified_path_is_frozen() -> None:
    cp = classify_path(".env")
    with pytest.raises((AttributeError, TypeError)):
        cp.sensitivity = PathSensitivity.LOW  # type: ignore[misc]


# ---------------------------------------------------------------------------
# classify_paths bulk helper
# ---------------------------------------------------------------------------

def test_classify_paths_returns_one_per_input() -> None:
    paths = [".env", "README.md", "app.py"]
    results = classify_paths(paths)
    assert len(results) == len(paths)
    for cp, original in zip(results, paths):
        assert isinstance(cp, ClassifiedPath)
        assert cp.path == original


def test_classify_paths_empty_list() -> None:
    assert classify_paths([]) == []


# ---------------------------------------------------------------------------
# Priority: CRITICAL beats HIGH when both rules could match
# ---------------------------------------------------------------------------

def test_critical_beats_high_for_secrets_yaml() -> None:
    # secrets.yaml matches both CRITICAL (secrets YAML) and HIGH (YAML config)
    result = classify_path("secrets.yaml")
    assert result.sensitivity == PathSensitivity.CRITICAL
