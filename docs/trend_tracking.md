# Trend Tracking

Vaultmap can track finding counts across successive scans, letting you spot whether your codebase is getting cleaner or accumulating new secrets over time.

## How It Works

After each scan the CLI records a `TrendEntry` in `.vaultmap/trends.json`.  Each entry contains:

| Field | Description |
|---|---|
| `timestamp` | UTC ISO-8601 time of the scan |
| `total_findings` | Total credential matches found |
| `by_severity` | Breakdown by severity level |
| `scanned_files` | Number of files inspected |

## Trend Label

When more than one scan has been recorded, vaultmap prints a trend label alongside the summary:

```
↑ +3 since last scan
↓ -2 since last scan
→ no change since last scan
```

## Storage Location

By default trends are stored in `.vaultmap/trends.json` relative to the working directory.  Add this path to `.gitignore` if you do not want to commit scan history, or commit it deliberately to share progress with your team.

## Programmatic Access

```python
from vaultmap.trend_tracker import load_trend_report, record_entry

# Record a new data point
record_entry(
    total_findings=scan_result.total,
    by_severity=scan_result.severity_counts,
    scanned_files=scan_result.file_count,
)

# Read the history
report = load_trend_report()
print(report.trend_label())   # e.g. "↑ +2 since last scan"
print(report.latest)          # most recent TrendEntry
print(report.delta())         # integer change, or None
```

## Resetting History

Delete `.vaultmap/trends.json` to start fresh.  The file is recreated automatically on the next scan.
