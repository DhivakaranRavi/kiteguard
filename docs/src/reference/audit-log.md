# Audit Log Reference

kiteguard appends one JSONL line per hook invocation to `~/.kiteguard/audit.log`.

## Record schema

```json
{
  "ts":             "2026-03-28T10:23:01.123Z",
  "hook":           "PreToolUse",
  "verdict":        "block",
  "rule":           "dangerous_command",
  "reason":         "matched /rm\\s+-rf/ in 'rm -rf /'",
  "user":           "alice",
  "host":           "macbook-pro",
  "repo":           "acme/frontend",
  "input_hash":     "a3f1c2…",
  "prev_hash":      "9b2e7f…",
  "tokens_in":      42,
  "policy_version": "1.0.0"
}
```

| Field            | Type    | Notes                                              |
|------------------|---------|----------------------------------------------------|
| `ts`             | string  | RFC 3339 timestamp                                 |
| `hook`           | string  | `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop` |
| `verdict`        | string  | `allow` or `block`                                 |
| `rule`           | string  | Matched rule name, or empty string on allow        |
| `reason`         | string  | Human-readable explanation, empty on allow         |
| `user`           | string  | OS username running Claude Code                    |
| `host`           | string  | Hostname of the machine                            |
| `repo`           | string  | Git repo path (e.g. `acme/frontend`)               |
| `input_hash`     | string  | SHA-256 hex of the input (prompt text or command)  |
| `prev_hash`      | string  | SHA-256 of the previous log entry (hash-chain)     |
| `tokens_in`      | integer | Estimated input tokens (added in v0.2.0)           |
| `policy_version` | string  | Version label from `rules.json` (added in v0.2.0) |

Prompt text is **never stored** in the log — only its hash. This ensures audit trails without leaking sensitive content.

## Querying with jq

Top blocked rules:
```bash
jq -r 'select(.verdict=="block") | .rule' ~/.kiteguard/audit.log \
  | sort | uniq -c | sort -rn
```

Activity in the last hour:
```bash
jq -r 'select(.ts > "2026-03-28T09:00:00Z")' ~/.kiteguard/audit.log
```

Block rate today:
```bash
jq -r '.verdict' ~/.kiteguard/audit.log | sort | uniq -c
```

## Rotation

kiteguard does not rotate the log automatically. Use `logrotate` or a cron job:

```
~/.kiteguard/audit.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
```
