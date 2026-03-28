# Secrets Detector

Detects hardcoded secrets and credential material in text inputs.

## Source

[`src/detectors/secrets.rs`](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/secrets.rs)

## Detected secret types

| Rule name          | Pattern                                     | Example                        |
|--------------------|---------------------------------------------|--------------------------------|
| `aws_access_key`   | `AKIA[0-9A-Z]{16}`                          | `AKIAIOSFODNN7EXAMPLE`         |
| `github_token_ghp` | `ghp_[A-Za-z0-9]{36}`                       | `ghp_16C7e42F292c6912E7710c838347Ae884b`   |
| `github_token_gho` | `gho_[A-Za-z0-9]{36}`                       | OAuth token                    |
| `github_token_ghs` | `ghs_[A-Za-z0-9]{36}`                       | App installation token         |
| `generic_api_key`  | `(?i)api[_\-]?key[\s:=]+['"A-Za-z0-9]{20,}`| `api_key = "abcdef123456..."`  |
| `jwt_token`        | `eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+` | Standard JWT |
| `private_key`      | `-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY` | PEM private key header        |
| `slack_token`      | `xox[baprs]-[0-9A-Za-z\-]{10,}`             | `xoxb-...`                     |
| `stripe_key`       | `sk_live_[A-Za-z0-9]{24}`                   | Stripe secret key              |
| `stripe_test_key`  | `sk_test_[A-Za-z0-9]{24}`                   | Stripe test key                |
| `bearer_token`     | `(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]{20,}` | HTTP auth header |
| `env_secret`       | `(?i)(SECRET|PASSWORD|PASSWD|API_SECRET)\s*=\s*[^\s]{8,}` | .env style secrets |

## Usage

The secrets detector runs on:
- File content returned by `Read` (PostToolUse)
- Web content returned by `WebFetch` (PostToolUse)
- Claude's final response (Stop)

It does **not** run on user prompts (PII detector handles those).

## Configuration

Secrets patterns are hardcoded and cannot be disabled via `rules.yaml`. This is intentional — secrets detection is a safety control, not a policy control.

## False positives

Generic patterns (`generic_api_key`, `bearer_token`, `env_secret`) may trigger on example values in documentation or test fixtures. If this is a problem in your workflow, file a GitHub issue rather than attempting to disable detection — we can tighten the patterns.
