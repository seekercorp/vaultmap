# Ignore Rules

Vaultmap supports path-based ignore rules so you can exclude files and
directories from scanning without modifying your source code.

## Default patterns

The following paths are ignored automatically:

| Pattern | Reason |
|---|---|
| `.git/**` | Version-control internals |
| `**/__pycache__/**` | Python bytecode cache |
| `**/*.pyc`, `**/*.pyo` | Compiled Python files |
| `node_modules/**` | JavaScript dependencies |
| `.venv/**`, `venv/**` | Python virtual environments |
| `*.egg-info/**` | Python package metadata |
| `dist/**`, `build/**` | Build artefacts |

To disable default patterns, pass `use_defaults=False` when constructing
an `IgnoreRules` instance or call `build_ignore_rules(use_defaults=False)`.

## Ignore file (`.vaultmapignore`)

Create a `.vaultmapignore` file in your project root to define additional
patterns.  The format is one glob per line; lines starting with `#` are
treated as comments.

```
# Ignore generated secrets fixture
tests/fixtures/secrets/**

# Ignore backup files
*.bak
```

Pass the file path to the CLI via `--ignore-file`:

```bash
vaultmap scan . --ignore-file .vaultmapignore
```

## Programmatic usage

```python
from vaultmap.ignore_rules import build_ignore_rules

rules = build_ignore_rules(
    extra_patterns=["*.log"],
    ignore_file=".vaultmapignore",
)

if not rules.is_ignored("src/config.py"):
    print("file will be scanned")

# Filter a list of paths
clean_paths = rules.filter(all_discovered_paths)
```

## Glob semantics

Patterns follow Python's `fnmatch` rules:

- `*` matches any sequence of characters within a single path segment.
- `**` matches across path separators (zero or more segments).
- `?` matches exactly one character.
- Patterns are matched against both the full relative path and the
  bare filename, so `*.pyc` will catch `src/utils/helper.pyc`.
