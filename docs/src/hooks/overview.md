# Hooks Overview

kiteguard intercepts at four Claude Code lifecycle hooks. Each fires at a different point in the agent's execution.

| Hook | When it fires | Primary threat |
|---|---|---|
| [UserPromptSubmit](user-prompt-submit.md) | Before prompt reaches Claude API | PII in prompt, prompt injection |
| [PreToolUse](pre-tool-use.md) | Before any tool executes | Dangerous commands, file access |
| [PostToolUse](post-tool-use.md) | After tool returns content | Injection in files, PII in read content |
| [Stop](stop.md) | After response is generated | Secrets/PII in Claude's output |

## Why all four are needed

No single hook covers every attack vector:

- **Only `UserPromptSubmit`**: Misses injections embedded in files Claude reads
- **Only `PreToolUse`**: Can't see file *contents*, only paths
- **Only `Stop`**: Damage already done before response

All four together provide complete coverage with no blind spots.
