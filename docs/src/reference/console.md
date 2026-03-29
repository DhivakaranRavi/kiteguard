# Console Reference

kiteguard includes a local web console for real-time visibility into all audit events.

## Launch

```bash
kiteguard serve
```

Open **http://localhost:7070** in your browser.

The console serves the built-in UI — no external network access required. All data is read from `~/.kiteguard/audit.log` on your local machine.

| Flag | Default | Description |
|------|---------|-------------|
| `--port <PORT>` | `7070` | TCP port to listen on |

---

## Panels

### Stats Bar

Four summary counters at the top of the page:

| Counter | Description |
|---------|-------------|
| **Total Events** | All hook invocations logged |
| **Blocked** | Events where verdict = `block` |
| **Allowed** | Events where verdict = `allow` |
| **Block Rate** | Percentage of events that were blocked |

### Threat Chart

A bar chart showing blocked events grouped by rule name (e.g. `secrets_leak`, `commands_exec`, `pii_exposure`, `prompt_injection`). Lets you see which policy rules are firing most.

### Timeline

A line chart showing event volume over time, split by `allow` (green) and `block` (red). Useful for spotting spikes in activity or sudden policy changes.

### Events Table

Paginated log of all hook invocations with filters.

**Columns:**

| Column | Description |
|--------|-------------|
| TIMESTAMP | RFC 3339 time of the hook invocation |
| HOOK | `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, or `Stop` |
| VERDICT | `✅ allow` or `🚫 block` |
| REPO | Git repository path (e.g. `acme/frontend`) |
| USER | OS username that triggered the event |

**Filter bar:**

- **VERDICT** dropdown — filter to `Allow` only, `Block` only, or all
- **HOOK** dropdown — filter to a specific hook type or all

Changing either filter resets to page 1 automatically.

**Pagination:** 100 events per page. Use `[← PREV]` / `[NEXT →]` buttons. The toolbar shows the current range (e.g. `1–100 of 847`).

### Event Detail Modal

Click any row in the Events Table to open a full-detail modal. The modal shows all fields including:

- Full timestamp
- Hook type and verdict
- Matched rule name
- **Reason** — human-readable explanation of why the event was blocked
- Repository, user, and host
- Input hash (SHA-256 of the prompt or command — the raw content is never stored)

Press **[× CLOSE]** or click outside the modal to dismiss.

---

## API Endpoints

The console backend exposes two JSON endpoints (used by the UI):

### `GET /api/stats`

Returns aggregate counters.

```json
{
  "total":      847,
  "blocked":    142,
  "allowed":    705,
  "block_rate": 16.8
}
```

### `GET /api/events`

Returns paginated, filtered events.

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page`    | `1`     | Page number (1-based) |
| `limit`   | `100`   | Events per page |
| `verdict` | _(all)_ | Filter: `allow` or `block` |
| `hook`    | _(all)_ | Filter: `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop` |

Response:

```json
{
  "total": 847,
  "page":  1,
  "limit": 100,
  "events": [
    {
      "ts":         "2026-03-28T10:23:01Z",
      "hook":       "PreToolUse",
      "verdict":    "block",
      "rule":       "secrets_leak",
      "reason":     "AWS secret key detected: AKIA... in Write tool argument",
      "user":       "alice",
      "host":       "macbook-pro",
      "repo":       "acme/frontend",
      "input_hash": "a3f1c2…",
      "prev_hash":  "9b2e7f…"
    }
  ]
}
```
