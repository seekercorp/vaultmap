# Allowlist

The allowlist lets you suppress known-safe findings so they don't clutter
reports. This is useful for test fixtures, example values in documentation,
or secrets that have already been rotated.

## File location

By default **vaultmap** looks for `.vaultmap-allowlist.json` in the current
working directory. You can override this with the `--allowlist` CLI flag:

```bash
vaultmap scan . --allowlist path/to/my-allowlist.json
```

## File format

The file is a JSON array of rule objects:

```json
[
  {
    "pattern": "AKIAIOSFODNN7EXAMPLE",
    "reason": "AWS example key from official docs",
    "paths": []
  },
  {
    "pattern": "ghp_[A-Za-z0-9]{36}",
    "reason": "Rotated token left in test fixture",
    "paths": ["tests/fixtures/"]
  }
]
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | ✅ | Regular expression matched against the **matched value** of a finding. |
| `reason` | ✅ | Human-readable explanation for why this value is safe to ignore. |
| `paths` | ❌ | List of path regexes. When non-empty the rule only suppresses findings in matching file paths. An empty list (or omitting the field) suppresses the pattern in **all** files. |

## How matching works

1. After a file (or git diff line) produces a `Match`, vaultmap checks whether
   the match's `value` satisfies any allowlist entry whose `paths` also cover
   the file path.
2. If a matching entry is found the `Match` is silently dropped before the
   report is generated.
3. The `reason` field is not currently surfaced in output but is preserved for
   audit purposes.

## Tips

- Use **anchored** patterns (`^…$`) when you want to suppress an exact string
  rather than any string that contains the pattern.
- Keep the allowlist in version control so the whole team benefits from
  suppressions and the rationale is documented via `reason`.
- Prefer **path-scoped** rules (`paths` non-empty) to minimise the risk of
  accidentally suppressing real secrets in production code.
