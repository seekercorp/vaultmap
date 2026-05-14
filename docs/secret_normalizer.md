# Secret Normalizer

The `vaultmap.secret_normalizer` module cleans up raw matched secret values
before they are compared, deduplicated, or displayed. This is especially useful
when the same credential appears in multiple forms across a codebase (e.g.
quoted in one file, prefixed with an assignment operator in another).

## Why Normalize?

A raw regex match often captures surrounding syntax noise:

```
SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
```

Without normalization, the matched value is `SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"`,
which differs from a bare `AKIAIOSFODNN7EXAMPLE` found elsewhere — even though
both represent the same credential.

## Transformations Applied

| Name | Description |
|---|---|
| `strip_assignment` | Removes a leading `KEY =` or `key:` prefix |
| `strip_quotes` | Removes surrounding single or double quotes |
| `collapse_whitespace` | Removes all internal whitespace characters |

Transformations are applied in order. Each one is recorded so callers can
understand exactly what was changed.

## API

### `normalize_value(raw: str) -> tuple[str, list[str]]`

Normalizes a raw string value. Returns `(normalized_value, transformations)`.

```python
from vaultmap.secret_normalizer import normalize_value

clean, transforms = normalize_value('SECRET = "abc123"')
# clean      -> "abc123"
# transforms -> ["strip_assignment", "strip_quotes"]
```

### `normalize_match(match: Match) -> NormalizedMatch`

Wraps a `Match` with its normalized value and the list of transformations that
were applied.

### `normalize_result(result: ScanResult) -> NormalizedResult`

Normalizes every match in a `ScanResult`, returning a `NormalizedResult`.

## Data Classes

### `NormalizedMatch`

| Field | Type | Description |
|---|---|---|
| `original` | `Match` | The original, unmodified match |
| `normalized_value` | `str` | Cleaned credential value |
| `transformations` | `list[str]` | Transformations applied |

Call `.to_dict()` to serialize for JSON output.

### `NormalizedResult`

| Field | Type | Description |
|---|---|---|
| `matches` | `list[NormalizedMatch]` | All normalized matches |
| `scanned_files` | `int` | Number of files scanned |
