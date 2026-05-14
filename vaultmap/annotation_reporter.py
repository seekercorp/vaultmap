"""Reporters for annotated scan results."""
from __future__ import annotations

import json
from typing import List

from vaultmap.reporter import _colorize
from vaultmap.secret_annotator import AnnotatedMatch, AnnotatedResult


def _severity_color(severity: str) -> str:
    mapping = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}
    return mapping.get(severity.lower(), "white")


def print_annotation_text_report(result: AnnotatedResult) -> None:
    annotations = result.annotations
    if not annotations:
        print(_colorize("green", "\u2714 No findings to annotate."))
        return

    print(_colorize("white", f"Annotation Report — {len(annotations)} finding(s)\n"))
    for ann in annotations:
        m = ann.match
        color = _severity_color(m.severity)
        header = _colorize(color, f"[{m.severity.upper()}] {m.pattern_name}")
        print(f"  {header}")
        print(f"    File : {m.path}:{m.line}")
        print(f"    Hint : {ann.hint}")
        for ref in ann.references:
            print(f"    Ref  : {ref}")
        print()


def print_annotation_json_report(result: AnnotatedResult) -> None:
    payload = {
        "total": len(result.annotations),
        "findings": [a.to_dict() for a in result.annotations],
    }
    print(json.dumps(payload, indent=2))
