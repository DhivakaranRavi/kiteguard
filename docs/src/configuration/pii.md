# PII Detection

kiteguard scans for personally identifiable information (PII) across three interception points:

- **UserPromptSubmit** — the user's own prompt
- **PostToolUse** — content returned from files or web pages Claude reads
- **Stop** — the final assistant response before delivery

## Configuration

```yaml
pii:
  enabled: true
  block_on_prompt: false   # redact from prompt, don't block
  block_on_response: true  # block if PII found in Claude's response
  types:
    - ssn
    - credit_card
    - email
    - phone_us
    - passport
```

## Fields

| Field              | Default | Description                                                  |
|--------------------|---------|--------------------------------------------------------------|
| `enabled`          | `true`  | Master toggle for all PII detection                          |
| `block_on_prompt`  | `false` | Block (exit 2) when PII found in user prompt                 |
| `block_on_response`| `true`  | Block response delivery when PII found in final response     |
| `types`            | all     | List of PII types to detect (omit a type to disable it)      |

## Supported PII types

| Type          | Example                        | Pattern description                        |
|---------------|--------------------------------|--------------------------------------------|
| `ssn`         | `123-45-6789`                  | US Social Security Number (dashes or dots) |
| `credit_card` | `4111 1111 1111 1111`          | Visa, Mastercard, Amex, Discover           |
| `email`       | `alice@example.com`            | Standard email address                     |
| `phone_us`    | `(555) 867-5309`               | US phone number (multiple formats)         |
| `passport`    | `A12345678`                    | US passport number                         |

## block_on_prompt vs block_on_response

| Setting             | Effect                                                             |
|---------------------|--------------------------------------------------------------------|
| `block_on_prompt: false` | PII in the user's prompt is logged but not blocked. Claude processes it — useful when the user intentionally pastes data to process. |
| `block_on_prompt: true`  | Blocks the request entirely. The user must remove PII before Claude sees it. |
| `block_on_response: true`| Blocks Claude's final reply if it contains PII — prevents Claude from echoing sensitive data back. |

## Notes

- All regex patterns are anchored to word boundaries to reduce false positives.
- Credit card detection uses a simplified Luhn-adjacent regex — it catches common formats but is not an authoritative validator.
- Prompt text is never stored in the audit log, only its hash.
