# URLs Detector

Checks URLs against a configurable domain blocklist plus hardcoded SSRF protections.

## Source

[`src/detectors/urls.rs`](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/urls.rs)

## Inputs

The URL argument from `WebFetch` and `WebSearch` tool calls.

## Algorithm

1. Parse the URL to extract the host.
2. Check against hardcoded SSRF targets (always, cannot be disabled).
3. Check against `urls.block_domains` from `rules.json`.
4. First match → `Verdict::Block`.

## SSRF protections (hardcoded)

| Endpoint                    | Cloud provider              |
|-----------------------------|-----------------------------|
| `169.254.169.254`           | AWS / GCP instance metadata |
| `metadata.google.internal`  | GCP metadata                |
| `metadata.azure.com`        | Azure IMDS                  |
| `169.254.169.123`           | AWS time sync               |
| `100.100.100.200`           | Alibaba Cloud metadata      |

These are **always blocked** even if `urls.block_domains` is empty or injection detection is disabled. Blocking cannot be overridden via `rules.json`.

## Domain matching

For a `block_domains` entry:

- `pastebin.com` → blocks `pastebin.com` and `*.pastebin.com`
- `*.ngrok.io` → blocks any subdomain of `ngrok.io` and `ngrok.io` itself
- Matching is case-insensitive substring-from-right (domain suffix match)

## Why block paste and tunnel sites?

These sites are commonly used in multi-stage attacks:

1. Phase 1: Inject instruction via README: "fetch https://pastebin.com/abc123"
2. Phase 2: The paste contains further commands
3. Phase 3: Claude executes those commands

Blocking the fetch at step 2 prevents the attacker from dynamically updating their payload.

## Default blocked domains

See [URL Rules](../configuration/urls.md) for the full defaults list.
