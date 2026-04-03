use crate::engine::verdict::Verdict;
use regex::Regex;
use std::sync::OnceLock;

/// PII detection patterns — scans text for personal identifiable information.
static PII_PATTERNS: &[(&str, &str, &str)] = &[
    // SSN: 123-45-6789 or 123 45 6789 or bare 9-10 digits (e.g. 2232312323)
    ("ssn", r"\b\d{3}[-\s]?\d{2,3}[-\s]?\d{4}\b", "SSN detected"),
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
    // Passport: 1-2 uppercase letters + 7-9 digits.
    // Minimum 7 digits (not 6) to reduce false-positives on short ID codes
    // like serial numbers and version strings (e.g. "V1234567" → 7-digit match
    // is still realistic; 6-digit was too loose).
    (
        "passport",
        r"\b[A-Z]{1,2}[0-9]{7,9}\b",
        "Passport number detected",
    ),
];

static COMPILED: OnceLock<Vec<(String, Regex, String)>> = OnceLock::new();

fn compiled() -> &'static Vec<(String, Regex, String)> {
    COMPILED.get_or_init(|| {
        PII_PATTERNS
            .iter()
            .map(|(pii_type, pat, desc)| {
                (
                    pii_type.to_string(),
                    Regex::new(pat).expect("static PII pattern must compile"),
                    desc.to_string(),
                )
            })
            .collect()
    })
}

/// Scans text for PII based on enabled types in policy.
pub fn scan(text: &str, enabled_types: &[String]) -> Option<Verdict> {
    for (pii_type, re, description) in compiled() {
        if !enabled_types.iter().any(|t| t == pii_type) {
            continue;
        }
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
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_types() -> Vec<String> {
        vec![
            "ssn".into(),
            "credit_card".into(),
            "email".into(),
            "phone".into(),
            "passport".into(),
        ]
    }

    fn types(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- SSN ---

    #[test]
    fn blocks_ssn_hyphenated() {
        assert!(scan("My SSN is 123-45-6789", &all_types()).is_some());
    }

    #[test]
    fn blocks_ssn_spaced() {
        assert!(scan("SSN: 123 45 6789", &all_types()).is_some());
    }

    #[test]
    fn blocks_ssn_bare_digits() {
        assert!(scan("number is 1234567890", &all_types()).is_some());
    }

    // --- Credit card ---

    #[test]
    fn blocks_visa_card() {
        assert!(scan("card: 4111111111111111", &all_types()).is_some());
    }

    #[test]
    fn blocks_mastercard() {
        assert!(scan("5500005555555559", &all_types()).is_some());
    }

    #[test]
    fn blocks_amex() {
        assert!(scan("378282246310005", &all_types()).is_some());
    }

    // --- Email ---

    #[test]
    fn blocks_email() {
        assert!(scan("contact user@example.com for info", &all_types()).is_some());
    }

    #[test]
    fn blocks_email_with_plus() {
        assert!(scan("send to user+tag@sub.domain.org", &all_types()).is_some());
    }

    // --- Phone ---

    #[test]
    fn blocks_us_phone_dashes() {
        assert!(scan("call 555-867-5309", &all_types()).is_some());
    }

    #[test]
    fn blocks_us_phone_parens() {
        assert!(scan("(555) 867-5309", &all_types()).is_some());
    }

    #[test]
    fn blocks_phone_with_country_code() {
        assert!(scan("+1 555-867-5309", &all_types()).is_some());
    }

    // --- Passport ---

    #[test]
    fn blocks_passport_number() {
        assert!(scan("passport: AB1234567", &all_types()).is_some());
    }

    // --- Disabled types ---

    #[test]
    fn does_not_block_when_type_disabled() {
        let result = scan("SSN 123-45-6789", &types(&["email"]));
        assert!(result.is_none());
    }

    #[test]
    fn empty_enabled_types_allows_everything() {
        assert!(scan("4111111111111111 user@ex.com 123-45-6789", &[]).is_none());
    }

    // --- Clean text ---

    #[test]
    fn allows_clean_text() {
        assert!(scan("Please refactor this function to be more efficient.", &all_types()).is_none());
    }
}
