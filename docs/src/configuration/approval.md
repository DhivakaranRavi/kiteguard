# Human Approval

```json
"approval": { "enabled": true, "block_instead_of_ask": true, "unknown_programs": false }
```

- `enabled` (default `true`): turn the approval rules off entirely.
- `block_instead_of_ask` (default `true`): approval-class actions (publish, deploy, send, mutating HTTP, DB writes) are blocked. Set it to `false` to ask a human instead, on hosts that can prompt (Claude Code, Copilot, Cursor).

- `unknown_programs` (default `false`): strict mode. Any program outside the built-in dev/read-only list asks for approval. More coverage, more prompts.

All default to the secure setting when the field is missing. See [Approval Detector](../detectors/approval.md).
