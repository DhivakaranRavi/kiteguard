# PII Detector

Detects personally identifiable information (PII) in text inputs.

## Source

[`src/detectors/pii.rs`](https://github.com/DhivakaranRavi/kiteguard/blob/main/src/detectors/pii.rs)

## Supported types

### SSN (US Social Security Number)

Pattern: `\b\d{3}[-\.]\d{2}[-\.]\d{4}\b`

Matches: `123-45-6789`, `123.45.6789`

---

### Credit Card

Patterns for major card networks (Visa, Mastercard, Amex, Discover):

```
# Visa: 4xxx xxxx xxxx xxxx
\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b

# Mastercard: 5[1-5]xx / 2[2-7]xx
\b(?:5[1-5]\d{2}|2[2-7]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b

# Amex: 34xx or 37xx (15 digits)
\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b

# Discover: 6011 / 65xx
\b6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b
```

---

### Email

Pattern: `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`

---

### Phone (US)

Pattern: `\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b`

Matches: `(555) 867-5309`, `+1-800-555-0100`, `5558675309`

---

### Passport (US)

Pattern: `\b[A-Z]{1,2}\d{6,9}\b`

---

## Limits

- Credit card matching is regex-based. It catches common formats but does not perform Luhn validation.
- The passport pattern matches US passport format; other countries are not currently detected.
- Phone matching is optimized for US numbers; international formats may produce false negatives.

## Behaviour

The PII detector is a reporter — it returns which PII type was found. The decision to block or allow is controlled by `pii.block_on_prompt` and `pii.block_on_response` in `rules.json`. See [PII Configuration](../configuration/pii.md).
