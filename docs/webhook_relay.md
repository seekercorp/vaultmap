# Webhook Relay

Vaultmap can forward scan findings to an external HTTP endpoint in real time.
This is useful for integrating with security dashboards, SIEM systems, or
custom alerting pipelines.

## Quick start

```bash
vaultmap scan ./src \
  --relay-url https://hooks.example.com/vaultmap \
  --relay-header "Authorization: Bearer $TOKEN"
```

## How it works

For every `Match` produced by a scan, `relay_match()` sends an HTTP `POST`
request containing a JSON payload to the configured URL.

### Default payload

```json
{
  "path": "src/config.py",
  "line": 42,
  "pattern": "aws_access_key",
  "severity": "critical"
}
```

> **Note:** The matched secret value is **not** included by default.
> Pass `--relay-include-value` to opt in — only do this over HTTPS.

## `RelayConfig` options

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | `str` | required | Webhook endpoint URL |
| `headers` | `dict` | `{}` | Extra HTTP headers (e.g. auth tokens) |
| `timeout` | `int` | `10` | Request timeout in seconds |
| `include_value` | `bool` | `False` | Include raw matched value in payload |

## `RelayReport`

After relaying all matches, `relay_result()` returns a `RelayReport`:

```python
report.sent    # number of successfully delivered records
report.failed  # number of failed deliveries
report.records # list[RelayRecord]
```

Each `RelayRecord` has a `.success` property and preserves the HTTP status
code or error message for debugging.

## Output formats

```bash
# Human-readable
vaultmap scan ./src --relay-url ... --relay-format text

# JSON
vaultmap scan ./src --relay-url ... --relay-format json
```

## Security considerations

- Always use HTTPS endpoints.
- Rotate webhook tokens regularly.
- Avoid `--relay-include-value` unless strictly necessary.
