# Webhook Integration

kiteguard can POST every block event to a webhook URL in real time — useful for SIEM integration, Slack alerts, or a central audit service.

## Configuration

```yaml
webhook:
  url: "https://your-siem.example.com/events"
  token: "Bearer eyJhbGciOi..."
  timeout_ms: 500
```

## Fields

| Field          | Required | Default | Description                                            |
|----------------|----------|---------|--------------------------------------------------------|
| `url`          | yes      | —       | HTTPS endpoint to POST events to                       |
| `token`        | no       | —       | Value of the `Authorization` header                    |
| `hmac_secret`  | no       | —       | Signs each POST with `X-KiteGuard-Signature` (v0.2.0)  |
| `timeout_ms`   | no       | `500`   | Request timeout; webhook failure never blocks Claude   |

## HMAC Signing (v0.2.0)

Set `hmac_secret` to enable request signing. Every webhook POST will include an `X-KiteGuard-Signature: sha256=<hex>` header so receivers can verify authenticity.

```yaml
webhook:
  enabled: true
  url: "https://your-siem.example.com/events"
  hmac_secret: "$KITEGUARD_WEBHOOK_SECRET"   # $ENV_VAR reference recommended
```

The signature is `HMAC-SHA256(secret, body)` encoded as lowercase hex, prefixed with `sha256=`.

### Verifying in your receiver (Node.js example)

```js
const crypto = require('crypto');

function verify(secret, body, header) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(header),
    Buffer.from(expected)
  );
}
```

> Using an env-var reference (`$KITEGUARD_WEBHOOK_SECRET`) keeps secrets out of `rules.json`. kiteguard resolves it at runtime.

## Payload format

```json
{
  "ts":         "2026-03-28T10:23:01.123Z",
  "hook":       "PreToolUse",
  "verdict":    "block",
  "rule":       "dangerous_command",
  "reason":     "matched /rm\\s+-rf/ in 'rm -rf /'",
  "input_hash": "a3f1c2d4…"
}
```

The payload is the same schema as the audit log. Prompt text is never included — only the hash.

## Behavior

- Only `block` verdicts trigger a webhook call. `allow` events are written to the local audit log but not sent.
- Webhook failures are **silent** — if the endpoint is unreachable or returns an error, kiteguard still enforces the verdict locally and logs it to `~/.kiteguard/audit.log`.
- Calls are fire-and-forget (best effort). kiteguard does not retry.

## Slack example

To send alerts to Slack, use an Incoming Webhook URL:

```yaml
webhook:
  url: "https://hooks.slack.com/services/T.../B.../..."
```

Slack expects a `{"text": "..."}` body — you will need a small adapter service or a middleware like n8n/Zapier to transform the payload.

For a direct integration, point `url` at a simple serverless function that reformats the event and forwards it to Slack.
