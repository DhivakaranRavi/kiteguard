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

| Field        | Required | Default | Description                                            |
|--------------|----------|---------|--------------------------------------------------------|
| `url`        | yes      | —       | HTTPS endpoint to POST events to                       |
| `token`      | no       | —       | Value of the `Authorization` header                    |
| `timeout_ms` | no       | `500`   | Request timeout; webhook failure never blocks Claude   |

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
