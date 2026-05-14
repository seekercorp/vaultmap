"""Annotate matches with human-readable remediation hints."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultmap.scanner import Match, ScanResult

# Map pattern name fragments to remediation advice.
_HINTS: Dict[str, str] = {
    "aws_access_key": "Rotate via AWS IAM console and remove from source.",
    "aws_secret": "Rotate via AWS IAM console and remove from source.",
    "github_token": "Revoke at github.com/settings/tokens and regenerate.",
    "private_key": "Regenerate the key pair and never commit private keys.",
    "generic_password": "Move to an environment variable or secrets manager.",
    "generic_secret": "Move to an environment variable or secrets manager.",
    "stripe": "Roll the key in the Stripe dashboard under API keys.",
    "slack": "Revoke via Slack app management and issue a new token.",
    "google_api": "Restrict or regenerate the key in Google Cloud Console.",
    "jwt": "Invalidate the signing secret and reissue tokens.",
    "database_url": "Rotate the database password and update your config.",
    "sendgrid": "Revoke and regenerate in the SendGrid API Keys page.",
    "twilio": "Rotate credentials in the Twilio console.",
    "heroku": "Revoke via Heroku Account settings > API Key.",
    "mailgun": "Reset the key in the Mailgun dashboard.",
}

_DEFAULT_HINT = "Rotate or revoke this credential and store it securely."


@dataclass
class AnnotatedMatch:
    match: Match
    hint: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        base = {
            "path": self.match.path,
            "line": self.match.line,
            "pattern": self.match.pattern_name,
            "severity": self.match.severity,
            "hint": self.hint,
        }
        if self.references:
            base["references"] = self.references
        return base


@dataclass
class AnnotatedResult:
    source_result: ScanResult
    annotations: List[AnnotatedMatch] = field(default_factory=list)


def _hint_for(pattern_name: str) -> str:
    key = pattern_name.lower()
    for fragment, hint in _HINTS.items():
        if fragment in key:
            return hint
    return _DEFAULT_HINT


def _references_for(pattern_name: str) -> List[str]:
    key = pattern_name.lower()
    if "aws" in key:
        return ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"]
    if "github" in key:
        return ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"]
    if "private_key" in key:
        return ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"]
    return []


def annotate_match(match: Match) -> AnnotatedMatch:
    return AnnotatedMatch(
        match=match,
        hint=_hint_for(match.pattern_name),
        references=_references_for(match.pattern_name),
    )


def annotate_result(result: ScanResult) -> AnnotatedResult:
    annotations = [annotate_match(m) for m in result.matches]
    return AnnotatedResult(source_result=result, annotations=annotations)
