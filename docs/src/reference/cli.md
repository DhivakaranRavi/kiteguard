# CLI Reference

## kiteguard init

Registers kiteguard hooks for a specific AI agent.

### Claude Code

Writes all four hooks to `~/.claude/settings.json` and creates the `~/.kiteguard/` config directory.

```bash
kiteguard init --claude-code
```

### Cursor

Writes 10 hooks (with `failClosed: true` on all blocking hooks) to both `.cursor/hooks.json` (project-level) and `~/.cursor/hooks.json` (user-level).

```bash
kiteguard init --cursor
```

### Gemini CLI

Writes hooks to `.gemini/settings.json` in the current project directory.

```bash
kiteguard init --gemini
```

Re-run after updating the binary. You can run multiple init commands to protect all agents simultaneously.

---

## kiteguard serve

Launches the local web dashboard at `http://localhost:7070`.

```bash
kiteguard serve
```

The dashboard provides a real-time view of all audit events with filtering, pagination, and block-reason detail. See the [Console reference](console.md) for full details.

| Flag | Default | Description |
|------|---------|-------------|
| `--port <PORT>` | `7070` | TCP port to listen on |

---

## kiteguard audit

Pretty-prints the local audit log.

```bash
kiteguard audit
```

Output:
```
TIMESTAMP                      HOOK                      VERDICT    RULE
2026-03-28T10:23:01Z           PreToolUse                🚫 block   dangerous_command
2026-03-28T10:24:10Z           UserPromptSubmit          ✅ allow
```

### kiteguard audit verify

Verifies the tamper-evident hash chain of the audit log.

```bash
kiteguard audit verify
```

Output on success:
```
✅  audit chain intact — 142 entries verified
```

Output on failure:
```
❌  hash mismatch at entry 87 — log may have been tampered with
```

---

## kiteguard policy

```bash
kiteguard policy list    # show active policy summary
kiteguard policy path    # print path to rules.json
kiteguard policy sign    # sign the current rules.json (HMAC-SHA256)
```

---

## kiteguard --version

```bash
kiteguard --version
# kiteguard 0.1.0
```
