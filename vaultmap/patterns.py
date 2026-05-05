"""Credential pattern definitions for secret scanning."""

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass
class CredentialPattern:
    name: str
    pattern: Pattern
    severity: str  # 'high', 'medium', 'low'
    description: str


RAW_PATTERNS = [
    (
        "aws_access_key",
        r"(?i)AKIA[0-9A-Z]{16}",
        "high",
        "AWS Access Key ID",
    ),
    (
        "aws_secret_key",
        r"(?i)aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key[\s]*[=:][\s]*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?",
        "high",
        "AWS Secret Access Key",
    ),
    (
        "github_token",
        r"ghp_[A-Za-z0-9]{36}",
        "high",
        "GitHub Personal Access Token",
    ),
    (
        "generic_api_key",
        r"(?i)(api[_\-]?key|apikey)[\s]*[=:][\s]*[\'\"]?([A-Za-z0-9\-_]{20,})[\'\"]?",
        "medium",
        "Generic API Key",
    ),
    (
        "private_key_header",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "high",
        "Private Key Block",
    ),
    (
        "password_assignment",
        r"(?i)(password|passwd|pwd)[\s]*[=:][\s]*[\'\"]([^\'\"{\s]{8,})[\'\"]?",
        "medium",
        "Hardcoded Password",
    ),
    (
        "jwt_token",
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "medium",
        "JSON Web Token (JWT)",
    ),
    (
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "high",
        "Slack Webhook URL",
    ),
]

PATTERNS: list[CredentialPattern] = [
    CredentialPattern(
        name=name,
        pattern=re.compile(raw_pattern),
        severity=severity,
        description=description,
    )
    for name, raw_pattern, severity, description in RAW_PATTERNS
]


def get_patterns_by_severity(severity: str) -> list[CredentialPattern]:
    """Return patterns filtered by severity level."""
    return [p for p in PATTERNS if p.severity == severity]
