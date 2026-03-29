use crate::engine::verdict::Verdict;
use regex::Regex;
use std::sync::OnceLock;

/// Secret/credential detection patterns.
/// NOTE: The generic "40-char alphanumeric" AWS secret pattern is intentionally
/// omitted — it matches git SHAs, base64, and random IDs causing massive false
/// positives. AWS secret keys are instead caught by the broader .env/token patterns.
static SECRET_PATTERNS: &[(&str, &str)] = &[
    // AWS Access Keys (highly specific prefix)
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    // GitHub tokens (prefixed formats)
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token"),
    (r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth token"),
    (r"\bghs_[A-Za-z0-9]{36}\b", "GitHub app token"),
    // Generic API key patterns
    (
        r#"(?i)api[_-]?key\s*[:=]\s*['"]*[A-Za-z0-9\-_\.]{20,}"#,
        "API key",
    ),
    // JWT tokens
    (
        r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
        "JWT token",
    ),
    // Private key headers
    (
        r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----",
        "Private key",
    ),
    // Slack tokens
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    // Stripe keys
    (r"\bsk_live_[A-Za-z0-9]{24,}\b", "Stripe live secret key"),
    (
        r"\bpk_live_[A-Za-z0-9]{24,}\b",
        "Stripe live publishable key",
    ),
    // Generic Bearer tokens
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}", "Bearer token"),
    // .env style secrets
    (
        r#"(?i)(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY)\s*=\s*['"]*[A-Za-z0-9\-_\.@#$%]{8,}"#,
        ".env secret value",
    ),
];

static COMPILED: OnceLock<Vec<(Regex, String)>> = OnceLock::new();

fn compiled() -> &'static Vec<(Regex, String)> {
    COMPILED.get_or_init(|| {
        SECRET_PATTERNS
            .iter()
            .map(|(pat, desc)| {
                (Regex::new(pat).expect("static secret pattern must compile"), desc.to_string())
            })
            .collect()
    })
}

/// Scans text for secrets and credentials.
pub fn scan(text: &str) -> Option<Verdict> {
    for (re, description) in compiled() {
        if re.is_match(text) {
            return Some(Verdict::block(
                "secret_detected",
                format!("{} detected in content", description),
            ));
        }
    }
    None
}
