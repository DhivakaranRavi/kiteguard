# Approval Detector

Some actions are not provably malicious but cannot be undone or reach outside the machine. A blocklist cannot list them all, and blocking them breaks legitimate work, so kiteguard returns a `Confirm` verdict and the host asks a human.

Runs after all block detectors, on shell commands only (`src/detectors/approval.rs`), using the structural shell parser, so `echo ok && npm publish` and `sudo npm publish` are seen.

| Rule | Examples |
|---|---|
| `approval_publish` | `npm/cargo/poetry publish`, `twine upload`, `gem push`, `docker push`, `gh release create` |
| `approval_deploy` | `kubectl apply/patch/scale`, `helm upgrade`, `terraform apply`, `pulumi up`, `vercel --prod`, `gh pr merge`, `aws ... update-service` |
| `approval_send` | `mail`, `sendmail`, `aws sns publish`, `aws ses send-email`, Twilio |
| `approval_payment` | Stripe create/refund/transfer/payout |
| `approval_api_write` | `curl -X POST/PUT/PATCH/DELETE` or a body flag to a non-local host, `gh api -X ...` |
| `approval_db_write` | `psql/mysql/sqlite3/mongo` writes, `redis-cli SET/DEL/...` |
| `approval_remote` | `ssh host 'sudo ...'` |

`--dry-run`, `--check`, `--simulate`, `--what-if` and requests to localhost are not gated.

## How the host is told

| Host | Event | Signal |
|---|---|---|
| Claude Code, Copilot | PreToolUse | stdout `permissionDecision: "ask"`, exit 0 |
| Cursor | preToolUse, beforeShellExecution, beforeMCPExecution | `{"permission":"ask",...}`, exit 0 |
| Gemini, other events, unknown hosts | any | degrades to a block |

A host that cannot prompt gets a block, never a silent allow.
