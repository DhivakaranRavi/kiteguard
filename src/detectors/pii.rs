use crate::engine::verdict::Verdict;
use regex::Regex;

/// PII detection patterns — scans text for personal identifiable information.
static PII_PATTERNS: &[(&str, &str, &str)] = &[
    // SSN: 123-45-6789 or 123 45 6789
    ("ssn", r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b", "SSN detected"),
    // Credit card: major card patterns
    (
        "credit_card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "Credit card number detected",
    ),
    // Email address
    (
        "email",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "Email address detected",
    ),
    // Phone: US formats
    (
        "phone",
        r"\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b",
        "Phone number detected",
    ),
    // Passport (generic)
    (
        "passport",
        r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        "Passport number detected",
    ),
];

/// Scans text for PII based on enabled types in policy.
pub fn scan(text: &str, enabled_types: &[String]) -> Option<Verdict> {
    for (pii_type, pattern, description) in PII_PATTERNS {
        if !enabled_types.iter().any(|t| t == pii_type) {
            continue;
        }
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(text) {
                return Some(Verdict::block(
                    format!("pii_{}", pii_type),
                    format!(
                        "{} — sending PII to Claude API is blocked by policy",
                        description
                    ),
                ));
            }
        }
    }
    None
}
