# Secret Scoring

Vaultmap's **composite secret scorer** assigns each finding a numeric score
(0–100) that reflects how dangerous or actionable it is, combining four
orthogonal signals.

## Score Breakdown

| Dimension   | Max pts | Source |
|-------------|---------|--------|
| Severity    | 40      | Pattern severity label (critical/high/medium/low) |
| Entropy     | 10      | Shannon entropy of the matched value |
| Validation  | 15      | Whether the secret passes plausibility checks |
| Path        | 10      | Sensitive filename fragments (`.env`, `secret`, …) |
| **Total**   | **100** | Capped at 100 |

## Usage

```python
from vaultmap.secret_scorer import score_result
from vaultmap.scanner import scan_directory

result = scan_directory(".", patterns)
scored = score_result(result)

# Top 10 riskiest matches
for s in scored.top(10):
    print(s.score, s.match.path, s.match.line_number)
```

You can supply optional enrichment maps:

```python
scored = score_result(
    result,
    entropy_map={(path, line): entropy_float, ...},
    plausible_set={(path, line), ...},
)
```

## Reporting

### Text

```python
from vaultmap.score_reporter import print_score_text_report
print_score_text_report(scored)
```

Sample output:

```
Top 3 scored findings
============================================================
  1. [CRITICAL ] [################----]  80/100
      .env:12 pattern=aws_access_key
      breakdown: severity=40, entropy=10, validation=15, path=10
```

### JSON

```python
from vaultmap.score_reporter import print_score_json_report
print_score_json_report(scored)
```

```json
{
  "scored_findings": [
    {"path": ".env", "line": 12, "pattern": "aws_access_key",
     "score": 80, "breakdown": {"severity": 40, "entropy": 10,
     "validation": 15, "path": 10}}
  ],
  "total": 1
}
```

## Score Thresholds

| Score range | Label    |
|-------------|----------|
| 75 – 100    | CRITICAL |
| 50 – 74     | HIGH     |
| 25 – 49     | MEDIUM   |
| 0  – 24     | LOW      |
