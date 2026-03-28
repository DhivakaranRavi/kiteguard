# UserPromptSubmit

This hook fires when you press Enter in Claude Code — before Claude has processed your message.

## What kiteguard checks

| Check              | Description                                             |
|--------------------|---------------------------------------------------------|
| Prompt injection   | Patterns like "ignore previous instructions"            |
| PII detection      | SSN, credit cards, emails, phone numbers, passport IDs  |

## Hook payload (stdin from Claude Code)

```json
{
  "hook_event_name": "UserPromptSubmit",
  "prompt": "Summarize these customer records: Alice, SSN 123-45-6789…"
}
```

## Verdicts

| Condition                                      | Exit code | Effect                              |
|------------------------------------------------|-----------|-------------------------------------|
| No match                                       | `0`       | Claude receives the prompt          |
| Injection pattern matched                      | `2`       | Request blocked, user sees error    |
| PII matched + `block_on_prompt: true`          | `2`       | Request blocked                     |
| PII matched + `block_on_prompt: false`         | `0`       | Audit logged, Claude proceeds       |
| kiteguard crashes                              | `2`       | Fail-closed                         |

## When to set `block_on_prompt: true`

Enable this if your organization's policy prohibits Claude from ever processing PII — even when the user intentionally submits it. This is appropriate for environments where Claude should only work with anonymized data.

Disable it (the default) if your users legitimately process data that may contain PII (e.g., helping parse a CSV file), and you only want to prevent PII from leaking back out through Claude's response.

## Audit log entry

```json
{
  "ts": "2026-03-28T10:23:01.123Z",
  "hook": "UserPromptSubmit",
  "verdict": "block",
  "rule": "pii_ssn",
  "reason": "SSN pattern matched in prompt",
  "input_hash": "a3f1c2…"
}
```
