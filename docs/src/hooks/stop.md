# Stop

The Stop hook fires when Claude has finished generating its final response — just before it is delivered to the user.

## What kiteguard checks

| Check           | Description                                                   |
|-----------------|---------------------------------------------------------------|
| Secrets         | AWS keys, GitHub tokens, JWTs, private key headers, etc.      |
| PII             | SSN, credit cards, emails, phones, passports                  |

This is the last line of defence: even if Claude extracted sensitive data during reasoning (from a file, env var, or tool result), this hook prevents it from reaching the user.

## Hook payload (stdin from Claude Code)

```json
{
  "hook_event_name": "Stop",
  "transcript": [
    { "role": "user",      "content": "What is the AWS key in .env.prod?" },
    { "role": "assistant", "content": "The key is AKIAIOSFODNN7EXAMPLE…" }
  ]
}
```

kiteguard extracts the last `assistant` message and scans it.

## Verdicts

| Situation                   | Exit code | Effect                              |
|-----------------------------|-----------|-------------------------------------|
| Response is clean           | `0`       | User sees the response              |
| Secret found in response    | `2`       | Response blocked                    |
| PII found + `block_on_response: true` | `2` | Response blocked           |
| PII found + `block_on_response: false` | `0` | Audit logged only          |
| kiteguard crashes           | `2`       | Fail-closed                         |

## Why block on Stop and not just PreToolUse?

PreToolUse blocks the action of reading a secret from a file. But secrets can also appear via:
- Claude remembering a value from training
- A value injected via `CLAUDE.md` context
- Multi-step tool chains where a secret is assembled from pieces

Stop catches all of these cases.
