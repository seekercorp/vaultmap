# Plugin System

Vaultmap supports external pattern plugins via Python
[entry-points](https://packaging.python.org/en/latest/specifications/entry-points/).
This lets third-party packages contribute additional `CredentialPattern` rules
without modifying vaultmap's source.

## How It Works

At scan time vaultmap calls `load_plugins()` which iterates every installed
package that advertises the `vaultmap_patterns` entry-point group.  Each
entry-point must be a **callable** (e.g. a module-level function) that returns
a `list[CredentialPattern]`.

Broken or incompatible plugins are logged as warnings and skipped — they will
never crash a scan.

## Writing a Plugin

### 1. Define your patterns

```python
# my_vaultmap_plugin/patterns.py
from vaultmap.patterns import CredentialPattern

def get_patterns():
    return [
        CredentialPattern(
            name="acme-api-key",
            pattern=r"ACME_[A-Z0-9]{32}",
            severity="high",
            description="ACME Corp API key",
        ),
    ]
```

### 2. Register the entry-point

In your `setup.cfg` (or `pyproject.toml`):

```ini
[options.entry_points]
vaultmap_patterns =
    acme = my_vaultmap_plugin.patterns:get_patterns
```

### 3. Install the plugin

```bash
pip install ./my-vaultmap-plugin
```

Vaultmap will automatically discover and load the plugin on the next run.

## Listing Installed Plugins

```python
from vaultmap.plugin_loader import list_plugins

print(list_plugins())  # ['acme', ...]
```

## Integration with the Scanner

The CLI merges plugin patterns with built-in patterns before scanning:

```
all_patterns = get_patterns_by_severity(min_severity) + load_plugins()
```

Plugin patterns respect all existing flags: `--severity`, `--allowlist`,
`--baseline`, and inline suppression comments.
