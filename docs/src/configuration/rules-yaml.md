# rules.json Reference

Place your config at `~/.kiteguard/rules.json`. If not present, secure built-in defaults apply.

Run `kiteguard policy path` to see the exact location.

## Full schema (v0.2.0)

```json
{
  "version": "1.0.0",
  "remote_policy_url": null,
  "bash": {
    "enabled": true,
    "block_on_error": true,
    "block_patterns": [],
    "allow_patterns": []
  },
  "file_paths": {
    "block_read": [],
    "allow_read": [],
    "block_write": [],
    "allow_write": []
  },
  "pii": {
    "block_in_prompt": true,
    "block_in_file_content": true,
    "redact_in_response": true,
    "types": ["ssn", "credit_card", "email", "phone"]
  },
  "urls": {
    "blocklist": [],
    "allowlist": []
  },
  "injection": {
    "enabled": true
  },
  "webhook": {
    "enabled": false,
    "url": "",
    "token": null,
    "hmac_secret": null
  }
}
```

## New fields in v0.2.0

| Field | Description |
|---|---|
| `version` | String label recorded in every audit log entry (e.g. `"1.0.0"`) |
| `remote_policy_url` | Fetch policy from a remote HTTPS URL on startup. Override with `KITEGUARD_POLICY_URL` env var |
| `bash.allow_patterns` | Regex patterns whose matches are always allowed, even if they also match a `block_pattern` |
| `file_paths.allow_read` | Glob patterns always allowed, even if they match `block_read` |
| `file_paths.allow_write` | Glob patterns always allowed, even if they match `block_write` |
| `urls.allowlist` | URL substrings always allowed, even if they match `blocklist` |
| `webhook.hmac_secret` | HMAC-SHA256 signing secret — adds `X-KiteGuard-Signature` header to every POST |

## Allow rules

Allow rules are checked **before** block rules. If an input matches an allow rule, it is permitted regardless of any matching block rule.

This enables fine-grained exceptions without disabling entire detectors:

```json
"bash": {
  "block_patterns": ["curl[^|]*\\|[^|]*(bash|sh)"],
  "allow_patterns": ["curl.*api\\.myorg\\.com.*\\|\\ bash"]
}
```

## Section reference

| Section | Description |
|---|---|
| [`bash`](bash.md) | Dangerous command detection |
| [`file_paths`](file-paths.md) | Sensitive path protection |
| [`pii`](pii.md) | PII detection and blocking |
| [`urls`](urls.md) | URL and SSRF blocking |
| [`injection`](injection.md) | Prompt injection detection |
| [`webhook`](webhook.md) | Central dashboard integration |
