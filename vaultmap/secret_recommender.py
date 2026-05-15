"""Provides remediation recommendations for detected secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from vaultmap.scanner import Match, ScanResult


_RECOMMENDATIONS: dict[str, list[str]] = {
    "aws_access_key": [
        "Rotate the AWS access key immediately via IAM console.",
        "Use IAM roles or environment variables instead of hardcoded keys.",
        "Enable AWS CloudTrail to audit key usage.",
    ],
    "github_token": [
        "Revoke the token at https://github.com/settings/tokens.",
        "Use GitHub Actions secrets or a secrets manager instead.",
        "Scope tokens to the minimum required permissions.",
    ],
    "private_key_header": [
        "Revoke and regenerate the private key immediately.",
        "Store private keys in a secrets manager (e.g. Vault, AWS Secrets Manager).",
        "Never commit private keys to version control.",
    ],
    "generic_password": [
        "Replace hardcoded password with an environment variable or secrets manager reference.",
        "Rotate the password in all affected systems.",
        "Audit access logs for unauthorized usage.",
    ],
}

_DEFAULT_RECOMMENDATIONS: list[str] = [
    "Remove or rotate the exposed credential immediately.",
    "Store secrets in a dedicated secrets manager.",
    "Add the file pattern to .vaultmapignore if it is a false positive.",
]


@dataclass
class RecommendedMatch:
    match: Match
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.match.path,
            "line": self.match.line,
            "pattern": self.match.pattern_name,
            "severity": self.match.severity,
            "recommendations": self.recommendations,
        }


@dataclass
class RecommendationReport:
    items: List[RecommendedMatch] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.items)

    def for_pattern(self, pattern_name: str) -> List[RecommendedMatch]:
        return [i for i in self.items if i.match.pattern_name == pattern_name]


def _recommendations_for(pattern_name: str) -> list[str]:
    for key, recs in _RECOMMENDATIONS.items():
        if key in pattern_name.lower():
            return list(recs)
    return list(_DEFAULT_RECOMMENDATIONS)


def recommend_match(match: Match) -> RecommendedMatch:
    """Return a RecommendedMatch with tailored remediation steps."""
    return RecommendedMatch(
        match=match,
        recommendations=_recommendations_for(match.pattern_name),
    )


def build_recommendation_report(result: ScanResult) -> RecommendationReport:
    """Build a full recommendation report from a ScanResult."""
    return RecommendationReport(
        items=[recommend_match(m) for m in result.matches]
    )
