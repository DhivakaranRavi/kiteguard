# How It Works

## Claude Code hook system

Claude Code provides a native lifecycle hook system. kiteguard registers itself as a hook handler in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "command": "/usr/local/bin/kiteguard" }],
    "PreToolUse":       [{ "command": "/usr/local/bin/kiteguard" }],
    "PostToolUse":      [{ "command": "/usr/local/bin/kiteguard" }],
    "Stop":             [{ "command": "/usr/local/bin/kiteguard" }]
  }
}
```

Claude Code invokes the kiteguard binary at each hook point, passing a JSON payload on stdin. kiteguard exits `0` (allow) or `2` (block).

## The four interception points

```
Developer types prompt
        │
        ▼
[1] UserPromptSubmit ── PII in prompt? Injection patterns? → BLOCK
        │ (if allowed)
        ▼
  Claude reasons about the task
        │
        ▼
[2] PreToolUse ──────── Dangerous command? Sensitive path? Bad URL? → BLOCK
        │ (if allowed)
        ▼
  Tool executes (file read, bash, web fetch...)
        │
        ▼
[3] PostToolUse ─────── Injection in file content? PII in file? → BLOCK
        │ (if allowed)
        ▼
  Claude generates response
        │
        ▼
[4] Stop ────────────── Secrets in response? PII leaked? → REDACT
        │
        ▼
  Developer sees safe response
```

## Fail-closed behavior

If kiteguard crashes or encounters an internal error, it exits `2` — blocking the action. It never fails open. This is configurable but on by default.

## Audit log

Every event — allowed or blocked — is written to `~/.kiteguard/audit.log` as append-only JSONL. Prompt content is never logged; only a hash is stored.
