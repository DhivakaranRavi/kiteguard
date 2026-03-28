# Changelog

All notable changes to kiteguard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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

---

## [0.1.0] - TBD

First public release.
