# Credential Redaction

Vaultmap can redact sensitive values before displaying or storing scan results,
so that secret material never appears in plain text in reports or logs.

## How it works

The `vaultmap.redactor` module provides helpers that operate at three levels:

| Function | Input | Output |
|---|---|---|
| `redact_value(value)` | Raw secret string | Partially-masked string |
| `redact_line(line, value)` | Source line + secret | Line with secret replaced |
| `redact_match(match)` | `Match` object | New `Match` with masked value/line |
| `redact_result(result)` | `ScanResult` | New `ScanResult` with all matches masked |

### Masking strategy

The first and last **4 characters** of a secret are preserved to help identify
which credential was found, while the middle is replaced with `*` characters:

```
AKIAIOSFODNN7EXAMPLE  →  AKIA************MPLE
```

Strings shorter than 8 characters are fully masked.

## CLI usage

Pass `--redact` to any scan command to enable redaction in the output:

```bash
vaultmap scan ./src --redact
vaultmap git-scan --redact
```

Redaction is applied **after** allowlist and suppression filtering, so the
baseline fingerprint and deduplication logic always operate on the real value.

## Programmatic usage

```python
from vaultmap.redactor import redact_result
from vaultmap.scanner import scan_directory

result = scan_directory(".")
safe_result = redact_result(result)
# safe_result.matches contain masked values only
```

## Notes

- Redaction is **one-way**: the original value cannot be recovered from the
  masked output.
- The `reveal` parameter of `redact_value` can be adjusted programmatically if
  a different number of visible characters is required.
- Audit log entries written with `--redact` will also contain only the masked
  values.
