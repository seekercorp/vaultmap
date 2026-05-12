# High-Entropy String Detection

Vaultmap includes a Shannon-entropy analyser that flags tokens which are
statistically likely to be secrets even when they don't match a known pattern.

## How it works

Every line of source code is scanned for contiguous runs of characters drawn
from two common secret character sets:

| Charset  | Minimum length | Entropy threshold |
|----------|---------------|-------------------|
| Base64   | 20 chars      | 4.5 bits/symbol   |
| Hex      | 20 chars      | 3.0 bits/symbol   |

If a token's [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
exceeds the threshold for its charset it is reported as a potential secret.

## Public API

```python
from vaultmap.entropy import high_entropy_matches, EntropyMatch

matches: list[EntropyMatch] = high_entropy_matches(line)
for m in matches:
    print(m.token, m.entropy, m.charset)
```

`EntropyMatch` fields:

- **token** – the raw matched string
- **entropy** – computed Shannon entropy (bits per symbol, rounded to 4 dp)
- **charset** – `"base64"` or `"hex"`

## Tuning thresholds

The thresholds `THRESHOLD_BASE64` and `THRESHOLD_HEX` are module-level
constants you can override at runtime if the defaults produce too many
false positives for your codebase:

```python
import vaultmap.entropy as ent
ent.THRESHOLD_BASE64 = 4.8  # stricter
```

## Integration with the scanner

The CLI flag `--entropy` (added in the same release) enables entropy scanning
alongside pattern-based detection.  Entropy findings are reported with severity
`medium` and the pattern name `high-entropy-<charset>`.
