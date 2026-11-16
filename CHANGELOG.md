# Changelog

All notable changes to kiteguard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.2.0] - 2026-04-03

### Added

#### Secrets Detection
- 8 new secret patterns: Anthropic API keys (`sk-ant-`), OpenAI API keys (`sk-`), HuggingFace tokens (`hf_`), GitLab PATs (`glpat-`), npm access tokens (`npm_`), SendGrid API keys (`SG.`), Twilio API keys (`SK`), and database connection strings (`postgres://`, `mysql://`, `mongodb://`, `redis://`)

#### Allowlists
- `bash.allow_patterns` — regex patterns that explicitly permit commands otherwise matched by `block_patterns`
- `file_paths.allow_read` / `file_paths.allow_write` — glob patterns that override path blocks
- `urls.allowlist` — substring patterns that override the URL blocklist
- Allow rules are evaluated before block rules (first-allow-wins over blocks)

#### Dangerous Bash Patterns (7 new defaults)
- Python/Perl interpreter one-liners
- Interactive reverse shells (`bash -i`, `sh -i`)
- `mkfifo` + netcat reverse shell
- Raw disk cloning (`dd if=`)
- Fork bomb (`:(){ :|:& };:`)

#### Token Tracking
- `tokens_in` field added to every audit log entry (estimated from input length)
- `tokens_total` field added to `/api/stats` response
- Tokens card added to the web console dashboard

#### Webhook HMAC Signing
- `webhook.hmac_secret` config field — value or `$ENV_VAR` reference
- Every webhook POST now includes `X-KiteGuard-Signature: sha256=<hex>` header when configured

#### Policy Hardening
- `policy_version` field added to every audit log entry
- `Policy.version` field — string label for the active policy
- `Policy.remote_policy_url` field — fetch policy from a remote HTTPS URL on startup
- `KITEGUARD_POLICY_URL` environment variable — override remote policy URL at runtime

#### Windows CI
- Added `x86_64-pc-windows-msvc` to the release matrix
- Windows release artifact is a `.zip` archive with SHA-256 checksum

#### New CLI Commands
- `kiteguard test <type> <input>` — dry-run any input against the live policy; exits 2 on block
  - Types: `prompt`, `command`, `read`, `write`, `url`
  - `--json` flag for machine-readable output
- `kiteguard explain [section]` — print every active rule with a human-readable description
  - Sections: `bash`, `paths`, `pii`, `urls`, `injection` (omit for all)

### Changed
- `config/rules.yaml` reference file updated with all new fields and examples
- `kiteguard init` now scaffolds a complete `rules.json` with all fields (including new v0.2.0 fields)
- `kiteguard --version` now reports `0.2.0`

---

## [0.1.0] - 2026-03-01

First public release.

### Added
- Initial project structure
- `PreToolUse` hook: dangerous command detection
- `UserPromptSubmit` hook: PII and prompt injection detection
- `PostToolUse` hook: file and web content scanning
- `Stop` hook: secret and PII redaction in responses
- YAML-based policy engine with secure defaults
- Append-only JSONL audit log at `~/.kiteguard/audit.log`
- Optional webhook sink for central dashboards
- CLI: `init`, `audit`, `policy` subcommands
- `scripts/install.sh` with checksum verification and build-from-source fallback
- `scripts/uninstall.sh`
