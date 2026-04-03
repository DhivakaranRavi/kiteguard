# UserPromptSubmit / beforeSubmitPrompt

This hook fires when you press Enter — before the agent has processed your message.

| Agent | Hook name |
|---|---|
| Claude Code | `UserPromptSubmit` |
| Cursor | `beforeSubmitPrompt` |

## What kiteguard checks

| Check | Description |
|---|---|
| Prompt injection | Patterns like "ignore previous instructions" |
| PII detection | SSN, credit cards, emails, phone numbers, passport IDs |

## Hook payload

**Claude Code:**
```json
{
  "hook_event_name": "UserPromptSubmit",
  "prompt": "Summarize these customer records: Alice, SSN 123-45-6789…"
}
```

**Cursor:**
```json
{
  "hookEventName": "beforeSubmitPrompt",
  "prompt": "Summarize these customer records: Alice, SSN 123-45-6789…"
}
```

## Verdicts

| Condition | Exit code | Effect |
|---|---|---|
| No match | `0` | Agent receives the prompt |
| Injection pattern matched | `2` | Request blocked, user sees error |
| PII matched + `block_on_prompt: true` | `2` | Request blocked |
| PII matched + `block_on_prompt: false` | `0` | Audit logged, agent proceeds |
| kiteguard crashes | `2` | Fail-closed |

## When to set `block_on_prompt: true`

Enable this if your organization's policy prohibits the agent from ever processing PII. Appropriate for environments where only anonymized data should be processed.

Disable it (the default) if users legitimately work with data that may contain PII and you only want to prevent PII from leaking out through the response.

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
