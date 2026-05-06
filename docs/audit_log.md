# Audit Log

Vaultmap can append a structured audit trail of every scan to a JSONL file.
Each line is a self-contained JSON object describing one scan event.

## Enabling the audit log

### Via environment variable

```bash
export VAULTMAP_AUDIT_LOG=/var/log/vaultmap/audit.jsonl
vaultmap scan ./src
```

### Via CLI flag

```bash
vaultmap scan ./src --audit-log audit.jsonl
vaultmap git-scan --audit-log audit.jsonl
```

If neither the flag nor the environment variable is set, no log file is written.

## Record format

### Filesystem scan (`event: scan`)

```json
{
  "event": "scan",
  "timestamp": "2024-06-01T12:00:00+00:00",
  "scanned_files": 42,
  "total_matches": 3,
  "files_with_findings": ["src/config.py", "infra/deploy.sh"]
}
```

### Git history scan (`event: git_scan`)

```json
{
  "event": "git_scan",
  "timestamp": "2024-06-01T12:01:00+00:00",
  "commits_scanned": 150,
  "total_matches": 1,
  "commits_with_findings": ["a3f9c12"]
}
```

## Analysing the log

Because each line is valid JSON you can use standard tools:

```bash
# Count critical events over time
jq 'select(.total_matches > 0)' audit.jsonl

# Summarise with Python
python - <<'EOF'
import json, pathlib
for line in pathlib.Path('audit.jsonl').read_text().splitlines():
    rec = json.loads(line)
    print(rec['timestamp'], rec['event'], rec['total_matches'])
EOF
```

## Notes

- The log file is created (including parent directories) on first write.
- Records are **appended**; the file is never truncated by vaultmap.
- Timestamps are always UTC ISO-8601.
