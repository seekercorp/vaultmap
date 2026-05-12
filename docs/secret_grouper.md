# Secret Grouper

The `vaultmap.secret_grouper` module provides utilities for aggregating scan
matches into named groups, making it easier to reason about findings at a
higher level.

## Overview

After a scan produces a `ScanResult`, the grouper can reorganise the matches
along three axes:

| Strategy | Groups by |
|---|---|
| `group_by_pattern` | Credential pattern name (e.g. `aws_access_key`) |
| `group_by_file` | File path where the match was found |
| `group_by_severity` | Severity level (`high`, `medium`, `low`) |

All three functions return a `GroupedReport` object.

## Data Model

### `MatchGroup`

```python
@dataclass
class MatchGroup:
    key: str          # grouping value
    matches: list     # Match objects in this group
```

Convenience properties:
- `.count` — number of matches in the group
- `.files` — sorted, deduplicated list of file paths
- `.to_dict()` — JSON-serialisable summary

### `GroupedReport`

```python
@dataclass
class GroupedReport:
    strategy: str        # 'pattern' | 'file' | 'severity'
    groups: list         # List[MatchGroup]
```

Convenience properties:
- `.total` — sum of all match counts across groups
- `.get(key)` — look up a group by key, returns `None` if absent
- `.to_dict()` — JSON-serialisable representation

## Usage

```python
from vaultmap.scanner import scan_directory
from vaultmap.secret_grouper import group_by_pattern, group_by_severity

result = scan_directory("/path/to/project")

by_pattern = group_by_pattern(result)
for group in by_pattern.groups:
    print(f"{group.key}: {group.count} match(es) in {group.files}")

by_sev = group_by_severity(result)
if high := by_sev.get("high"):
    print(f"{high.count} high-severity findings")
```

## Integration with CLI

The `--group-by` flag (available in `vaultmap scan`) accepts `pattern`,
`file`, or `severity` and prints the grouped summary before the full
finding list.
