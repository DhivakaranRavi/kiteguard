use regex::Regex;
use crate::engine::verdict::Verdict;

/// Secret/credential detection patterns.
static SECRET_PATTERNS: &[(&str, &str)] = &[
    // AWS Access Keys
    (r"\bAKIA[0-9A-Z]{16}\b",                    "AWS access key"),
    // AWS Secret Keys (40 char base62)
    (r"\b[0-9a-zA-Z/+]{40}\b",                   "Possible AWS secret key"),
    // GitHub tokens
    (r"\bghp_[A-Za-z0-9]{36}\b",                 "GitHub personal access token"),
    (r"\bgho_[A-Za-z0-9]{36}\b",                 "GitHub OAuth token"),
    (r"\bghs_[A-Za-z0-9]{36}\b",                 "GitHub app token"),
    // Generic API key patterns
    (r#"(?i)api[_-]?key\s*[:=]\s*['"]*[A-Za-z0-9\-_\.]{20,}"#, "API key"),
    // JWT tokens
    (r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", "JWT token"),
    // Private key headers
    (r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----", "Private key"),
    // Slack tokens
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    // Stripe keys
    (r"\bsk_live_[A-Za-z0-9]{24,}\b",           "Stripe live secret key"),
    (r"\bpk_live_[A-Za-z0-9]{24,}\b",           "Stripe live publishable key"),
    // Generic Bearer tokens  
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}",   "Bearer token"),
    // .env style secrets
    (r#"(?i)(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY)\s*=\s*['"]*[A-Za-z0-9\-_\.@#$%]{8,}"#, ".env secret value"),
];

/// Scans text for secrets and credentials.
pub fn scan(text: &str) -> Option<Verdict> {
    for (pattern, description) in SECRET_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(text) {
                return Some(Verdict::block(
                    "secret_detected",
                    format!("{} detected in content", description),
                ));
            }
        }
    }
    None
}
