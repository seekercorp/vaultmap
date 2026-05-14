# Secret Tagger

The `secret_tagger` module automatically assigns human-readable **tags** to
each credential match. Tags help you filter, group, and prioritise findings
without needing to inspect raw pattern names.

## Tag categories

| Prefix | Example | Meaning |
|--------|---------|---------|
| `cloud:` | `cloud:aws` | Cloud provider credential |
| `vcs:` | `vcs:github` | Version-control service token |
| `crypto:` | `crypto:private-key` | Cryptographic material |
| `auth:` | `auth:api-key` | Generic authentication secret |
| `data:` | `data:database` | Database connection string |
| `comms:` | `comms:slack` | Messaging / communication service |
| `payment:` | `payment:stripe` | Payment processor credential |
| `entropy:` | `entropy:high` | Value has high Shannon entropy |
| `format:` | `format:multiline` | Value spans multiple lines |

Tags are derived from the pattern name and the matched value itself; a single
match may carry multiple tags.

## API

```python
from vaultmap.secret_tagger import tag_match, tag_result, tags_summary

# Tag a single Match object
tagged = tag_match(match)
print(tagged.tags)          # e.g. ['cloud:aws', 'entropy:high']
print(tagged.to_dict())     # serialisable dict

# Tag every match in a ScanResult
tagged_list = tag_result(scan_result)

# Aggregate tag frequencies
summary = tags_summary(tagged_list)
# {'auth:token': 3, 'cloud:aws': 1, ...}
```

## CLI integration

When running `vaultmap scan` with `--format grouped` the tagger is applied
automatically and tag counts are included in the summary footer.

## Extending tags

To add custom tag rules, edit `_PATTERN_TAG_MAP` in `vaultmap/secret_tagger.py`
or contribute additional entries via the plugin system (see `docs/plugin_system.md`).
