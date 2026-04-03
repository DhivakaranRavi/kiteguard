# How It Works

kiteguard is a single static Rust binary that integrates with AI agent hook systems. When an agent is about to take an action, it calls kiteguard — kiteguard inspects the payload, runs detectors, and exits `0` (allow) or `2` (block).

## Claude Code

Claude Code provides a native lifecycle hook system. kiteguard registers in `~/.claude/settings.json`:

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

```
User prompt
    │
[1] UserPromptSubmit ── PII? Injection? → BLOCK
    │
[2] PreToolUse ──────── Dangerous cmd? Bad path? Bad URL? → BLOCK
    │
  tool executes
    │
[3] PostToolUse ─────── Injection in output? PII? → BLOCK
    │
[4] Stop ────────────── Secrets in response? → REDACT
    │
  safe response
```

## Cursor

Cursor's hook system fires at 10 distinct points. kiteguard registers in `.cursor/hooks.json` (project-level) and `~/.cursor/hooks.json` (user-level) with `failClosed: true` on all blocking hooks:

```json
{
  "beforeSubmitPrompt":   [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "preToolUse":           [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "beforeShellExecution": [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "beforeReadFile":       [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "beforeMCPExecution":   [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "beforeTabFileRead":    [{ "command": "/usr/local/bin/kiteguard", "failClosed": true }],
  "postToolUse":          [{ "command": "/usr/local/bin/kiteguard" }],
  "afterShellExecution":  [{ "command": "/usr/local/bin/kiteguard" }],
  "afterMCPExecution":    [{ "command": "/usr/local/bin/kiteguard" }],
  "afterAgentResponse":   [{ "command": "/usr/local/bin/kiteguard" }]
}
```

```
User prompt
    │
[1] beforeSubmitPrompt ── PII? Injection? → BLOCK
    │
[2] preToolUse ─────────── Tool call inspection → BLOCK
[3] beforeShellExecution ─ Dangerous cmd? → BLOCK
[4] beforeReadFile ──────── Sensitive path? → BLOCK
[5] beforeMCPExecution ──── MCP SSRF? Injection? → BLOCK
[6] beforeTabFileRead ────── Sensitive tab path? → BLOCK
    │
  action executes
    │
[7]  postToolUse ──────── Tool output for injection/PII → LOG
[8]  afterShellExecution ─ Shell output → LOG
[9]  afterMCPExecution ─── MCP result for secrets → LOG
[10] afterAgentResponse ── Final response for PII → LOG
    │
  safe response
```

Client is auto-detected via the `CURSOR_PROJECT_DIR` environment variable.

## Gemini CLI

Gemini CLI calls kiteguard with a JSON payload and reads a `{"decision":"allow"}` / `{"decision":"deny", ...}` JSON response on stdout.

```json
{
  "hooks": {
    "before_tool": "/usr/local/bin/kiteguard",
    "after_tool":  "/usr/local/bin/kiteguard"
  }
}
```

## Fail-closed behavior

If kiteguard crashes or encounters an internal error, it exits `2` — blocking the action. It never fails open. For Cursor, `failClosed: true` is set in the hooks config so Cursor itself also blocks if the process fails to start.

## Audit log

Every event — allowed or blocked — is written to `~/.kiteguard/audit.log` as append-only JSONL. Prompt content is never logged; only a SHA-256 hash is stored. The log has a tamper-evident hash chain.
