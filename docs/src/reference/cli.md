# CLI Reference

## kiteguard init

Registers all four hooks in `~/.claude/settings.json` and creates the `~/.kiteguard/` config directory.

```bash
kiteguard init
```

Run this once after installation. Re-run after updating the binary.

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
