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

## kiteguard test

Dry-run any input against the active policy without blocking a real tool call. Useful for validating policy changes in CI or local development.

```bash
kiteguard test <type> <input>
kiteguard test --json <type> <input>   # machine-readable JSON output
```

### Types

| Type | What is tested |
|------|----------------|
| `prompt` | User prompt text (PII + injection) |
| `command` | Bash command (dangerous pattern check) |
| `read` | File path (read path check) |
| `write` | File path (write path check) |
| `url` | URL (SSRF + blocklist check) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Input would be allowed |
| `1` | Usage error (bad arguments) |
| `2` | Input would be blocked |

### Examples

```bash
kiteguard test command "rm -rf /"
# ✗  BLOCK
#    type:   command
#    input:  rm -rf /
#    rule:   dangerous_command
#    reason: matched /rm\s+-rf\s+// in 'rm -rf /'

kiteguard test --json url "http://169.254.169.254/latest"
# {"verdict":"block","type":"url","input":"http://169.254.169.254/latest","rule":"ssrf","reason":"..."}

kiteguard test read "~/.ssh/id_rsa"
# ✗  BLOCK
```

### Using in CI

```yaml
# .github/workflows/policy-check.yml
- name: Validate policy
  run: |
    kiteguard test command "rm -rf /" && exit 1 || true   # should block
    kiteguard test command "ls -la"                        # should allow
```

---

## kiteguard explain

Print every active rule in human-readable form. Use this after editing `rules.json` to confirm the policy looks correct.

```bash
kiteguard explain              # explain all sections
kiteguard explain bash         # bash block/allow patterns only
kiteguard explain paths        # file path rules
kiteguard explain pii          # PII types
kiteguard explain urls         # URL blocklist and allowlist
kiteguard explain injection    # injection detector status
```

### Example output

```
kiteguard — Active Policy Explanation
======================================
Policy version: 1.0.0

[bash] Command execution protection
  Status: ENABLED
  Fail-closed: true

  Block patterns (18):
    - curl[^|]*\|[^|]*(bash|sh)  →  Blocks download-and-execute pipe attacks
    - rm\s+-rf\s+/               →  Blocks recursive force-delete of critical directories
    ...

[paths] File path protection
  Blocked reads (7):
    - **/.ssh/**
    ...
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
# kiteguard 0.2.0
```
