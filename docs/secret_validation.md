# Secret Validation

Vaultmap includes a lightweight heuristic validator that helps distinguish
likely-real credentials from test values, placeholders, and dummy data —
without making any network requests.

## Overview

After scanning, each `Match` can be passed through the validator to receive a
`ValidatedMatch` that carries a `is_plausible` flag and a human-readable
`reason` explaining the verdict.

## Usage

```python
from vaultmap.secret_validator import validate_result, plausible_only

# result is a ScanResult from vaultmap.scanner
validated = validate_result(result)

# Keep only matches that look like real secrets
real_secrets = plausible_only(validated)
for v in real_secrets:
    print(v.match.path, v.match.value, v.reason)
```

## Heuristics Applied

| Check | Marks as | Reason |
|---|---|---|
| Value shorter than 8 characters | implausible | `value too short` |
| Contains a placeholder fragment (e.g. `example`, `your_`, `changeme`) | implausible | `placeholder fragment '<word>'` |
| All characters identical (e.g. `aaaaaaa`) | implausible | `uniform character repetition` |
| Passes all checks | plausible | `passed heuristic checks` |

### Placeholder Fragments

The following substrings (case-insensitive) cause a value to be marked
implausible:

`example`, `placeholder`, `your_`, `<your`, `xxxx`, `1234567890`,
`abcdefgh`, `test`, `dummy`, `fake`, `changeme`, `insert_`, `replace_`,
`todo`

## API Reference

### `validate_match(match: Match) -> ValidatedMatch`

Validate a single `Match` and return a `ValidatedMatch`.

### `validate_result(result: ScanResult) -> List[ValidatedMatch]`

Validate every match in a `ScanResult`.

### `plausible_only(validated: List[ValidatedMatch]) -> List[ValidatedMatch]`

Filter a validated list to only entries where `is_plausible` is `True`.

### `ValidatedMatch.to_dict() -> dict`

Serialise the validated match to a plain dictionary suitable for JSON output.

## Limitations

Heuristic validation cannot guarantee a secret is real. It is intended to
reduce noise from committed example configuration files and documentation
snippets. Always review flagged matches manually before taking action.
