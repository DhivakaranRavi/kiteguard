# File Path Rules

The `file_paths` section controls which files Claude is allowed to read or write.

## Configuration

```yaml
file_paths:
  block_read:
    - "~/.ssh/**"
    - "~/.gnupg/**"
    - "**/.env"
    - "**/*.pem"
    - "**/*.key"

  block_write:
    - "~/.claude/settings.json"
    - "~/.bashrc"
    - "~/.zshrc"
    - "~/.profile"
    - "/etc/**"
    - "/usr/**"
```

## Fields

| Field          | Description                                         |
|----------------|-----------------------------------------------------|
| `block_read`   | Glob patterns — Claude cannot read matching paths   |
| `block_write`  | Glob patterns — Claude cannot write matching paths  |

## Glob syntax

kiteguard uses a hand-rolled `glob_to_regex` function so there is no dependency on a glob crate. Supported patterns:

| Pattern | Matches                              |
|---------|--------------------------------------|
| `*`     | Any characters except `/`            |
| `**`    | Any characters including `/`         |
| `?`     | Any single character except `/`      |
| `[…]`   | Character class                       |

`~` at the start of a path is expanded to the current user's home directory.

## Why block `~/.claude/settings.json`?

A compromised prompt could instruct Claude to remove kiteguard's own hooks from the settings file. Blocking writes to this path makes kiteguard self-protecting by default.

## Disabling a default path rule

Remove the pattern from your `~/.kiteguard/rules.yaml`. There is no `disabled` flag.

> **Warning:** Removing `~/.claude/settings.json` from `block_write` allows Claude to modify its own hook configuration. Only do this if you fully understand the implications.
