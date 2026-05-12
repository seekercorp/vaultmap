"""Classify file paths into sensitivity categories to aid risk prioritisation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional


class PathSensitivity(str, Enum):
    CRITICAL = "critical"   # secrets / credentials almost certainly live here
    HIGH = "high"           # config / environment files
    MEDIUM = "medium"       # source code, scripts
    LOW = "low"             # docs, tests, assets


@dataclass(frozen=True)
class ClassifiedPath:
    path: str
    sensitivity: PathSensitivity
    reason: str


_RULES: List[tuple[re.Pattern[str], PathSensitivity, str]] = [
    # CRITICAL
    (re.compile(r"(^|/)\.(env)(\.[^/]+)?$", re.I), PathSensitivity.CRITICAL, ".env file"),
    (re.compile(r"(^|/)secrets?[^/]*\.ya?ml$", re.I), PathSensitivity.CRITICAL, "secrets YAML"),
    (re.compile(r"(^|/)credentials(\.\w+)?$", re.I), PathSensitivity.CRITICAL, "credentials file"),
    (re.compile(r"(^|/)\.netrc$", re.I), PathSensitivity.CRITICAL, ".netrc file"),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"), PathSensitivity.CRITICAL, "SSH key file"),
    (re.compile(r"\.pem$", re.I), PathSensitivity.CRITICAL, "PEM certificate/key"),
    (re.compile(r"\.p12$|\.pfx$", re.I), PathSensitivity.CRITICAL, "PKCS12 keystore"),
    # HIGH
    (re.compile(r"(^|/)config(\.\w+)?$", re.I), PathSensitivity.HIGH, "config file"),
    (re.compile(r"\.ya?ml$", re.I), PathSensitivity.HIGH, "YAML config"),
    (re.compile(r"\.toml$", re.I), PathSensitivity.HIGH, "TOML config"),
    (re.compile(r"\.ini$|\.cfg$|\.conf$", re.I), PathSensitivity.HIGH, "INI/conf file"),
    (re.compile(r"(^|/)docker-compose[^/]*\.ya?ml$", re.I), PathSensitivity.HIGH, "Docker Compose file"),
    (re.compile(r"(^|/)Dockerfile(\.\w+)?$"), PathSensitivity.HIGH, "Dockerfile"),
    # MEDIUM
    (re.compile(r"\.py$|\.js$|\.ts$|\.go$|\.rb$|\.java$|\.sh$|\.bash$", re.I), PathSensitivity.MEDIUM, "source file"),
    (re.compile(r"\.tf$|\.tfvars$", re.I), PathSensitivity.MEDIUM, "Terraform file"),
    # LOW
    (re.compile(r"(^|/)tests?/", re.I), PathSensitivity.LOW, "test directory"),
    (re.compile(r"(^|/)docs?/", re.I), PathSensitivity.LOW, "docs directory"),
    (re.compile(r"\.md$|\.rst$|\.txt$", re.I), PathSensitivity.LOW, "documentation file"),
]


def classify_path(path: str) -> ClassifiedPath:
    """Return the highest-severity classification that matches *path*."""
    best: Optional[tuple[PathSensitivity, str]] = None
    order = list(PathSensitivity)  # CRITICAL first
    for pattern, sensitivity, reason in _RULES:
        if pattern.search(path):
            if best is None or order.index(sensitivity) < order.index(best[0]):
                best = (sensitivity, reason)
    if best:
        return ClassifiedPath(path=path, sensitivity=best[0], reason=best[1])
    return ClassifiedPath(path=path, sensitivity=PathSensitivity.LOW, reason="unrecognised file type")


def classify_paths(paths: List[str]) -> List[ClassifiedPath]:
    """Classify a list of paths, returning one :class:`ClassifiedPath` per entry."""
    return [classify_path(p) for p in paths]
