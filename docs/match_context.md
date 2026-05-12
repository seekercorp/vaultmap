# Match Context

Vaultmap can display the lines of source code **surrounding** each detected
credential, making it easier to understand how a secret is used and whether it
is a genuine finding.

## How it works

When context extraction is enabled, `vaultmap.match_context` reads the source
file and captures a configurable window of lines around every match:

```
  line N-2   ← before
  line N-1   ← before
> line N      ← matched line
  line N+1   ← after
  line N+2   ← after
```

The default window is **2 lines** on each side (`DEFAULT_CONTEXT_LINES = 2`).

## Public API

### `extract_context(path, line_number, lines=None, context_lines=2)`

Returns a `MatchContext` dataclass for a single match.

| Parameter | Type | Description |
|---|---|---|
| `path` | `str` | Path to the source file |
| `line_number` | `int` | 1-based line number of the match |
| `lines` | `list[str] \| None` | Pre-split lines (skips disk read) |
| `context_lines` | `int` | Lines to include before/after |

### `enrich_result_with_context(matches, context_lines=2)`

Accepts any iterable of objects with `.path` and `.line_number` attributes
(e.g. `scanner.Match`) and returns a `list[MatchContext]`.  File contents are
cached so each file is read **at most once**.

### `MatchContext`

```python
@dataclass
class MatchContext:
    path: str
    line_number: int
    before: list[str]
    matched: str
    after: list[str]

    def to_dict(self) -> dict: ...
```

## CLI integration

Pass `--context` (or `-C`) to the `scan` sub-command to enable context output
in both text and JSON reports:

```bash
vaultmap scan ./src --context
vaultmap scan ./src --context --format json
```

## Notes

- Binary files and files that cannot be decoded as UTF-8 are handled gracefully
  — undecodable bytes are replaced and context is still returned.
- If the file no longer exists at report time an empty `MatchContext` is
  returned rather than raising an exception.
