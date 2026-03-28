---
name: Bug Report
about: Report unexpected behavior or a false positive/negative
labels: ["type: bug"]
---

**Describe the bug**
A clear description of what happened.

**Hook involved**
- [ ] UserPromptSubmit
- [ ] PreToolUse
- [ ] PostToolUse
- [ ] Stop

**kiteguard version**
Run `kiteguard --version`

**OS and architecture**
e.g. macOS arm64, Linux x86_64

**Steps to reproduce**
1. ...

**Expected behavior**
What should have happened.

**Actual behavior**
What actually happened. Include the blocked/allowed verdict if relevant.

**Audit log entry**
Run `kiteguard audit` and paste the relevant line (redact sensitive data).
