"""Reporters for the secret recommendation feature."""
from __future__ import annotations

import json

from vaultmap.reporter import _colorize
from vaultmap.secret_recommender import RecommendationReport

_SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


def print_recommendation_text_report(report: RecommendationReport) -> None:
    """Print a human-readable remediation guide to stdout."""
    if not report.items:
        print(_colorize("green", "No findings — nothing to remediate."))
        return

    print(_colorize("bold", f"Remediation Recommendations ({len(report.items)} finding(s))\n"))

    for item in report.items:
        color = _SEVERITY_COLORS.get(item.match.severity.lower(), "white")
        header = (
            f"[{item.match.severity.upper()}] "
            f"{item.match.path}:{item.match.line} "
            f"({item.match.pattern_name})"
        )
        print(_colorize(color, header))
        for idx, rec in enumerate(item.recommendations, 1):
            print(f"  {idx}. {rec}")
        print()


def print_recommendation_json_report(report: RecommendationReport) -> None:
    """Print the recommendation report as JSON."""
    payload = {
        "total": len(report.items),
        "recommendations": [item.to_dict() for item in report.items],
    }
    print(json.dumps(payload, indent=2))
