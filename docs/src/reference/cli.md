# CLI Reference

## kiteguard init

Registers all four hooks in `~/.claude/settings.json` and creates the `~/.kiteguard/` config directory.

```bash
kiteguard init
```

Run this once after installation. Re-run after updating the binary.

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

---

## kiteguard policy

```bash
kiteguard policy list    # show active policy summary
kiteguard policy path    # print path to rules.json
```

---

## kiteguard --version

```bash
kiteguard --version
# kiteguard 0.1.0
```
