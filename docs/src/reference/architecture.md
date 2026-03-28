# Architecture

## Overview

kiteguard is a single static Rust binary. No runtime, no dependencies, no daemon.

## Source structure

```
src/
├── main.rs              — entrypoint, hook dispatcher, fail-closed logic
├── hooks/               — one handler per Claude Code hook
│   ├── pre_prompt.rs    — UserPromptSubmit
│   ├── pre_tool.rs      — PreToolUse
│   ├── post_tool.rs     — PostToolUse
│   └── post_response.rs — Stop
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

## Data flow

```
stdin JSON
    │
    ▼
main.rs → parse payload → load policy → dispatch by CLAUDE_HOOK_EVENT
    │
    ▼
hooks/*.rs → engine/evaluator.rs → detectors/*.rs
    │
    ▼
Verdict: Allow | Block | Redact
    │
    ├── audit/logger.rs → ~/.kiteguard/audit.log
    ├── audit/webhook.rs → optional HTTP POST
    └── exit(0) or exit(2) → Claude Code reads this
```

## Design principles

- **Fail-closed** — crashes block, never allow
- **No prompt content in logs** — only hashes stored
- **Single binary** — no install friction
- **Pure detectors** — no side effects, easy to test
- **Local first** — zero network calls unless webhook is explicitly configured
