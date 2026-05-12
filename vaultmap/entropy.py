"""Shannon entropy helpers for high-entropy string detection."""
from __future__ import annotations

import math
import re
from typing import List, NamedTuple

# Character sets commonly found in secrets
_BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX_CHARS = "0123456789abcdefABCDEF"

# Minimum token length worth analysing
_MIN_LENGTH = 20

# Entropy thresholds (bits per symbol)
THRESHOLD_BASE64 = 4.5
THRESHOLD_HEX = 3.0


class EntropyMatch(NamedTuple):
    token: str
    entropy: float
    charset: str  # 'base64' | 'hex'


def _shannon(token: str) -> float:
    """Return Shannon entropy (bits per symbol) for *token*."""
    if not token:
        return 0.0
    freq = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _tokens_for_charset(text: str, charset: str) -> List[str]:
    """Extract contiguous runs of *charset* characters from *text*."""
    pattern = "[" + re.escape(charset) + "]{" + str(_MIN_LENGTH) + ",}"
    return re.findall(pattern, text)


def high_entropy_matches(line: str) -> List[EntropyMatch]:
    """Return all high-entropy tokens found in *line*."""
    results: List[EntropyMatch] = []

    for token in _tokens_for_charset(line, _BASE64_CHARS):
        e = _shannon(token)
        if e >= THRESHOLD_BASE64:
            results.append(EntropyMatch(token=token, entropy=round(e, 4), charset="base64"))

    for token in _tokens_for_charset(line, _HEX_CHARS):
        e = _shannon(token)
        if e >= THRESHOLD_HEX:
            # avoid duplicating tokens already captured as base64
            if not any(r.token == token for r in results):
                results.append(EntropyMatch(token=token, entropy=round(e, 4), charset="hex"))

    return results
