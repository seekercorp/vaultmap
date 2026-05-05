# vaultmap

Lightweight secret scanning utility that maps credential patterns across local codebases and git history.

---

## Installation

```bash
pip install vaultmap
```

Or install from source:

```bash
git clone https://github.com/yourname/vaultmap.git && cd vaultmap && pip install .
```

---

## Usage

Scan the current directory:

```bash
vaultmap scan .
```

Scan including full git history:

```bash
vaultmap scan . --history
```

Output results as JSON:

```bash
vaultmap scan /path/to/project --format json --output report.json
```

**Example output:**

```
[FOUND] AWS Access Key  →  src/config.py:14
[FOUND] Generic API Key →  .env.backup:3
[FOUND] Private Key PEM →  scripts/deploy.sh:42

3 secrets found across 2 commits and 47 files scanned.
```

### Options

| Flag | Description |
|------|-------------|
| `--history` | Include git commit history in scan |
| `--format` | Output format: `text` (default) or `json` |
| `--output` | Write results to a file instead of stdout |
| `--ignore` | Comma-separated list of paths to exclude |

---

## License

This project is licensed under the [MIT License](LICENSE).