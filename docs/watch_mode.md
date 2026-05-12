# Watch Mode

Vaultmap can monitor a directory in real time and alert you the moment a new
credential is written to disk — before it ever reaches a commit.

## CLI usage

```bash
vaultmap watch ./src
```

Optional flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--interval` | `2.0` | Seconds between filesystem polls |
| `--baseline` | *(none)* | Path to a baseline file; already-known findings are suppressed |
| `--ext` | *(all)* | Comma-separated list of extensions to watch, e.g. `py,env,yaml` |
| `--format` | `text` | Output format: `text` or `json` |

## Programmatic API

```python
from pathlib import Path
from vaultmap.watchdog import watch
from vaultmap.scanner import Match

def alert(path: Path, matches: list[Match]) -> None:
    for m in matches:
        print(f"[{m.severity}] {path}:{m.line_number}  {m.pattern_name}")

watch(
    root=Path("./src"),
    on_finding=alert,
    interval=2.0,
    baseline_path=Path(".vaultmap_baseline.json"),
)
```

## How it works

1. On each poll cycle, every file under `root` is stat-checked.
2. Files whose `mtime` has changed since the last cycle are re-scanned.
3. New matches are compared against the **in-session baseline** (and an
   optional on-disk baseline file) so you are only notified about genuinely
   new secrets.
4. Acknowledged findings are written back to the baseline file so they are
   suppressed in future runs.

## Integration tips

- Run `vaultmap watch` in a pre-commit hook side-car or as a background
  process in your IDE.
- Combine with `--baseline .vaultmap_baseline.json` and commit the baseline
  file so the whole team shares the same suppression list.
- Use `--ext py,env,yaml,json` to limit noise from compiled artefacts.
