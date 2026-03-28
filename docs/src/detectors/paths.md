# Paths Detector

Checks file paths (from Read, Write, Edit tool calls) against glob-pattern blocklists.

## Source

[`src/detectors/paths.rs`](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/paths.rs)

## Inputs

The `file_path` argument from any file tool call:

- `Read` → checked against `block_read`
- `Write` / `Edit` → checked against `block_write`

## Algorithm

1. Expand `~` to the user's home directory in both the pattern and the input path.
2. Convert each glob pattern to a regex via `glob_to_regex()`.
3. For each compiled pattern, call `regex.is_match(path)`.
4. First match → `Verdict::Block { rule: "blocked_path", reason: "path '…' matches glob '…'" }`.

## glob_to_regex conversion

| Glob token | Regex equivalent  |
|------------|-------------------|
| `**`       | `.*`              |
| `*`        | `[^/]*`           |
| `?`        | `[^/]`            |
| `[…]`      | `[…]` (passed through) |
| Other      | `regex::escape(c)` |

## Examples

| Glob pattern       | Matches                                              |
|--------------------|------------------------------------------------------|
| `~/.ssh/**`        | Any file under `~/.ssh/`                             |
| `**/.env`          | `.env` in any directory                              |
| `**/*.pem`         | Any `.pem` file anywhere                             |
| `/etc/**`          | Any file under `/etc/`                               |

## Self-protection

`~/.claude/settings.json` is in the default `block_write` list. This prevents Claude from modifying its own hook configuration — an attacker cannot instruct Claude to disable kiteguard by writing to settings.
