# Human Approval

```json
"approval": { "enabled": true, "block_instead_of_ask": false, "unknown_programs": false }
```

- `enabled` (default `true`): turn the approval rules off entirely.
- `block_instead_of_ask` (default `false`): turn every approval into a block. Use it for unattended runs where nobody can answer a prompt.

- `unknown_programs` (default `false`): strict mode. Any program outside the built-in dev/read-only list asks for approval. More coverage, more prompts.

All default to the secure setting when the field is missing. See [Approval Detector](../detectors/approval.md).
