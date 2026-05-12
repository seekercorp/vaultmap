# Inline Suppression

Vaultmap lets you silence specific findings directly in source code using
special comments.  This is useful when a credential-like string is intentionally
present (e.g. a test fixture or a documentation example).

## Inline suppression

Append `# vaultmap: ignore` to any line you want skipped:

```python
DUMMY_KEY = "AKIAIOSFODNN7EXAMPLE"  # vaultmap: ignore
```

The tag is **case-insensitive**, so `# VaultMap: IGNORE` also works.

## Block suppression

Wrap a range of lines with `ignore-start` / `ignore-end` markers:

```python
# vaultmap: ignore-start
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# vaultmap: ignore-end
```

All lines between (and including) the markers are excluded from scanning.

> **Warning**: An `ignore-start` marker without a matching `ignore-end` will
> suppress all remaining lines in the file and emit a warning.  Always close
> every block you open.

## Suppression in non-Python files

The same comment syntax works in any file type that supports `#`-style comments
(e.g. YAML, Shell, Ruby).  For languages that use other comment styles, use the
appropriate single-line comment prefix followed by `vaultmap: ignore`:

```javascript
const DUMMY_KEY = "AKIAIOSFODNN7EXAMPLE"; // vaultmap: ignore
```

```xml
<!-- vaultmap: ignore-start -->
<accessKey>AKIAIOSFODNN7EXAMPLE</accessKey>
<!-- vaultmap: ignore-end -->
```

## Precedence

Inline suppression is applied **before** the allowlist and baseline checks.
If a line is suppressed it will never appear in the report, regardless of
other configuration.

## CLI flag

To disable inline suppression entirely (e.g. for a strict audit), pass
`--no-inline-suppress` on the command line:

```bash
vaultmap scan . --no-inline-suppress
```

> **Note**: Suppressed lines are not shown in reports.  If you need an audit
> trail of intentionally ignored secrets, use the allowlist feature instead.
