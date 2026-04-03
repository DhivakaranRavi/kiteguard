# Hooks Overview

kiteguard integrates with the native hook system of each supported AI agent. The number of interception points varies by agent.

## Claude Code hooks

| Hook | When it fires | Primary threat |
|---|---|---|
| [UserPromptSubmit](user-prompt-submit.md) | Before prompt reaches Claude API | PII in prompt, prompt injection |
| [PreToolUse](pre-tool-use.md) | Before any tool executes | Dangerous commands, file access |
| [PostToolUse](post-tool-use.md) | After tool returns content | Injection in files, PII in read content |
| [Stop](stop.md) | After response is generated | Secrets/PII in Claude's output |

## Cursor hooks

| Hook | When it fires | Primary threat |
|---|---|---|
| `beforeSubmitPrompt` | Before prompt is sent | PII, prompt injection |
| `preToolUse` | Before any tool call | Dangerous tool use |
| `beforeShellExecution` | Before a shell command runs | Dangerous commands |
| `beforeReadFile` | Before a file is read | Sensitive path access |
| `beforeMCPExecution` | Before an MCP tool executes | SSRF, command injection, secrets |
| `beforeTabFileRead` | Before tab context file is read | Sensitive path access |
| `postToolUse` | After tool returns | Injection in tool output |
| `afterShellExecution` | After shell command completes | Injection in shell output |
| `afterMCPExecution` | After MCP tool returns | Secrets in MCP result |
| `afterAgentResponse` | After the final response | PII/secrets in response |

All six `before*` hooks are registered with `failClosed: true` — if kiteguard fails to start, Cursor blocks the action.

## Gemini CLI hooks

| Hook | When it fires |
|---|---|
| `before_tool` | Before any tool executes |
| `after_tool` | After any tool returns |

## Why all hooks are needed

No single hook covers every attack vector:

- **Only a prompt hook**: Misses injections embedded in files the agent reads
- **Only a pre-tool hook**: Can't see file *contents*, only paths
- **Only a post-response hook**: Damage is already done before the response

All hooks together provide complete coverage with no blind spots.
