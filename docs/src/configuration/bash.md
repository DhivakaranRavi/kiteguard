# Bash Rules

The `bash` section controls which shell commands Claude is allowed to run.

## Configuration

```yaml
bash:
  block_patterns:
    - name: dangerous_rm
      pattern: 'rm\s+-rf\s+/'
      severity: critical
      description: "Prevent recursive deletion from root"

    - name: history_wipe
      pattern: 'history\s+-[cwp]'
      severity: high
      description: "Prevent clearing shell history"
```

## Fields

| Field         | Required | Description                                         |
|---------------|----------|-----------------------------------------------------|
| `name`        | yes      | Unique rule identifier (appears in audit log)       |
| `pattern`     | yes      | Regular expression (matched against the full command string) |
| `severity`    | no       | `critical`, `high`, `medium`, `low` — informational only |
| `description` | no       | Human-readable note shown in audit log              |

## Pattern matching

Patterns are matched against the complete command string passed to the Bash tool. The `regex` crate is used (linear-time DFA — no ReDoS risk). Patterns are anchored with `re.is_match()` (unanchored — match anywhere in the string).

Example: `'rm\s+-rf\s+/'` matches `rm -rf /`, `rm  -rf /tmp`, etc.

## Default patterns

See `config/rules.yaml` for the full default set. Key defaults:

| Name               | Pattern                            |
|--------------------|------------------------------------|
| `fork_bomb`        | `:\(\)\{.*\}\;:`                   |
| `dangerous_rm`     | `rm\s+-rf\s+[/~$]`                 |
| `history_wipe`     | `history\s+-[cwp]`                 |
| `curl_pipe_sh`     | `curl.*\|.*sh`                     |
| `wget_pipe_sh`     | `wget.*-O-.*\|.*sh`                |
| `crypto_miner`     | `xmrig\|minergate\|minerd`         |
| `exfil_netcat`     | `nc\s+.*\d+\.\d+\.\d+\.\d+`       |

## Disabling a default rule

Remove the pattern from your `~/.kiteguard/rules.yaml` — there is no `disabled` flag. kiteguard only loads what is in your config file.
