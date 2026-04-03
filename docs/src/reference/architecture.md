# Architecture

## Overview

kiteguard is a single static Rust binary. No runtime, no dependencies, no daemon.

## Source structure

```
src/
├── main.rs              — entrypoint, client detection, hook dispatcher, fail-closed logic
├── hooks/               — one handler per hook event
│   ├── pre_prompt.rs    — UserPromptSubmit / beforeSubmitPrompt
│   ├── pre_tool.rs      — PreToolUse / preToolUse / beforeShellExecution / beforeReadFile / beforeMCPExecution / beforeTabFileRead
│   ├── post_tool.rs     — PostToolUse / postToolUse / afterShellExecution / afterMCPExecution
│   └── post_response.rs — Stop / afterAgentResponse
├── detectors/           — pure detection logic, no side effects
│   ├── commands.rs      — dangerous bash patterns
│   ├── injection.rs     — prompt injection
│   ├── paths.rs         — sensitive file paths
│   ├── pii.rs           — SSN, CC, email, phone
│   ├── secrets.rs       — API keys, tokens, credentials
│   └── urls.rs          — URL blocklist + SSRF
├── engine/
│   ├── policy.rs        — loads rules.json, provides defaults
│   ├── evaluator.rs     — routes inputs through detectors
│   └── verdict.rs       — Allow / Block / Redact enum
└── audit/
    ├── logger.rs        — append-only JSONL audit log
    └── webhook.rs       — optional HTTP event sink
```

## Client detection

`main.rs` auto-detects which agent called kiteguard:

```
CLAUDE_HOOK_EVENT env set     → Claude Code path
CURSOR_PROJECT_DIR env set    → Cursor path
hookEventName in JSON payload → Cursor path (fallback)
hook_event_name in JSON payload → Gemini CLI path
```

This ensures correct response format (exit code vs JSON stdout) and correct event routing.

## Data flow

```
stdin JSON
    │
    ▼
main.rs → detect client → parse payload → load policy → dispatch by event name
    │
    ▼
hooks/*.rs → engine/evaluator.rs → detectors/*.rs
    │
    ▼
Verdict: Allow | Block | Redact
    │
    ├── audit/logger.rs → ~/.kiteguard/audit.log
    ├── audit/webhook.rs → optional HTTP POST
    └── exit(0) or exit(2)   → Claude Code / Cursor reads exit code
           — OR —
        JSON stdout          → Gemini CLI reads {"decision":"allow/deny"}
```

## Block response formats

| Agent | Allow | Block |
|---|---|---|
| Claude Code | exit `0` | exit `2` |
| Cursor | exit `0`, stdout `{}` | exit `2` |
| Gemini CLI | exit `0`, stdout `{"decision":"allow"}` | exit `0`, stdout `{"decision":"deny", "reason":"..."}` |

## Key components

| Component | Doc | Source |
|---|---|---|
| Policy / rules.json | [rules.json Reference](../configuration/rules-yaml.md) | [policy.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/engine/policy.rs) |
| Command detector | [Command Detector](../detectors/commands.md) | [commands.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/commands.rs) |
| Path detector | [Path Detector](../detectors/paths.md) | [paths.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/paths.rs) |
| PII detector | [PII Detector](../detectors/pii.md) | [pii.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/pii.rs) |
| Secrets detector | [Secrets Detector](../detectors/secrets.md) | [secrets.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/secrets.rs) |
| Injection detector | [Injection Detector](../detectors/injection.md) | [injection.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/injection.rs) |
| URL / SSRF detector | [URL Detector](../detectors/urls.md) | [urls.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/urls.rs) |
| Audit log | [Audit Log](audit-log.md) | [logger.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/audit/logger.rs) |
| Webhook | [Webhook Integration](../configuration/webhook.md) | [webhook.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/audit/webhook.rs) |
| CLI | [CLI Reference](cli.md) | [cli/mod.rs](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/cli/mod.rs) |

## Design principles

- **Fail-closed** — crashes block, never allow
- **No prompt content in logs** — only SHA-256 hashes stored
- **Single binary** — no install friction
- **Pure detectors** — no side effects, easy to test
- **Local first** — zero network calls unless webhook is explicitly configured
