# URL Blocking

The `urls` section controls which external domains Claude is allowed to fetch via `WebFetch` and `WebSearch`.

## Configuration

```yaml
urls:
  block_domains:
    - "pastebin.com"
    - "ngrok.io"
    - "*.ngrok.io"
    - "requestbin.com"
    - "webhook.site"
    - "burpcollaborator.net"
    - "interactsh.com"
```

## Fields

| Field           | Description                                                         |
|-----------------|---------------------------------------------------------------------|
| `block_domains` | List of domain strings or glob patterns to block                    |

## Matching rules

- A domain entry of `pastebin.com` blocks any URL whose host equals `pastebin.com` or ends in `.pastebin.com`.
- A pattern of `*.ngrok.io` blocks all subdomains of `ngrok.io` including `ngrok.io` itself.
- Matching is case-insensitive.

## Hardcoded SSRF protections

The following endpoints are **always blocked** regardless of `rules.yaml`:

| Host                      | Why                                        |
|---------------------------|--------------------------------------------|
| `169.254.169.254`         | AWS/GCP instance metadata service          |
| `metadata.google.internal`| GCP metadata service                       |
| `metadata.azure.com`      | Azure IMDS                                 |
| `169.254.169.123`         | AWS NTP / time sync                        |

These protect against Server-Side Request Forgery (SSRF) attacks where a malicious prompt could cause Claude to exfiltrate cloud credentials. They cannot be disabled via config.

## Why block pastebin-style sites?

Attackers commonly use paste sites to host second-stage payloads. A prompt injection in a web page might instruct Claude to `WebFetch` a pastebin URL containing further commands. Blocking such domains breaks this attack chain.
