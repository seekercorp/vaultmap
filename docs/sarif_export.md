# SARIF Export

vaultmap can emit scan results in [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) format, making it easy to integrate with GitHub Advanced Security, VS Code, and other SARIF-aware tools.

## Usage

Pass `--format sarif` to the `scan` command:

```bash
vaultmap scan ./my-project --format sarif > results.sarif
```

Or pipe directly into a file for GitHub upload:

```bash
vaultmap scan . --format sarif --severity high > vaultmap.sarif
```

## GitHub Actions Integration

```yaml
- name: Run vaultmap
  run: vaultmap scan . --format sarif > vaultmap.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vaultmap.sarif
```

## Output Structure

The SARIF document contains a single **run** with:

| Field | Description |
|---|---|
| `tool.driver.rules` | One entry per unique pattern ID found |
| `results` | One entry per individual match |
| `invocations` | Execution metadata including end timestamp |

### Severity Mapping

vaultmap severities map to SARIF levels as follows:

| vaultmap | SARIF level |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |

## Programmatic Use

```python
from vaultmap.output_formatter import build_sarif
from vaultmap.scanner import scan_directory

result = scan_directory("/path/to/repo")
doc = build_sarif(result)   # plain Python dict
```
