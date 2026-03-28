# rules.json Reference

Place your config at `~/.kiteguard/rules.json`. If not present, secure built-in defaults apply.

Run `kiteguard policy path` to see the exact location.

## Full schema

```json
{
  "version": 1,
  "bash": {
    "enabled": true,
    "block_on_error": true,
    "block_patterns": []
  },
  "file_paths": {
    "block_read": [],
    "block_write": []
  },
  "pii": {
    "block_in_prompt": true,
    "block_in_file_content": true,
    "redact_in_response": true,
    "types": ["ssn", "credit_card", "email", "phone"]
  },
  "urls": {
    "blocklist": []
  },
  "injection": {
    "enabled": true
  },
  "webhook": {
    "enabled": false,
    "url": "",
    "token": ""
  }
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
