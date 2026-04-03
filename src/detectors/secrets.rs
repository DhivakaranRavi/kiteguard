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
    // ── v0.2 additions ────────────────────────────────────────────────────────
    // Anthropic API key (sk-ant-<service>-<base64>)
    (r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b", "Anthropic API key"),
    // OpenAI API key (sk-<40+ chars, no dashes so doesn't overlap Anthropic/Stripe)
    (r"\bsk-[A-Za-z0-9]{40,}\b", "OpenAI API key"),
    // HuggingFace User Access Token
    (r"\bhf_[A-Za-z0-9]{30,}\b", "HuggingFace token"),
    // GitLab Personal Access Token
    (
        r"\bglpat-[A-Za-z0-9_\-]{20}\b",
        "GitLab personal access token",
    ),
    // npm access token
    (r"\bnpm_[A-Za-z0-9]{36}\b", "npm access token"),
    // SendGrid API key
    (
        r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b",
        "SendGrid API key",
    ),
    // Twilio API Key SID
    (r"\bSK[0-9a-fA-F]{32}\b", "Twilio API key"),
    // Generic database connection strings with embedded credentials
    (
        r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]{6,}@",
        "database connection string with credentials",
    ),
];

static COMPILED: OnceLock<Vec<(Regex, String)>> = OnceLock::new();

fn compiled() -> &'static Vec<(Regex, String)> {
    COMPILED.get_or_init(|| {
        SECRET_PATTERNS
            .iter()
            .map(|(pat, desc)| {
                (
                    Regex::new(pat).expect("static secret pattern must compile"),
                    desc.to_string(),
                )
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- AWS ---

    #[test]
    fn blocks_aws_access_key() {
        assert!(scan("key: AKIAIOSFODNN7EXAMPLE").is_some());
    }

    // --- GitHub tokens ---

    #[test]
    fn blocks_github_pat() {
        assert!(scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12").is_some());
    }

    #[test]
    fn blocks_github_oauth() {
        assert!(scan("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12").is_some());
    }

    #[test]
    fn blocks_github_app_token() {
        assert!(scan("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12").is_some());
    }

    // --- JWT ---

    #[test]
    fn blocks_jwt() {
        assert!(
            scan("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456abc123def456abc1").is_some()
        );
    }

    // --- Private key ---

    #[test]
    fn blocks_rsa_private_key_header() {
        assert!(scan("-----BEGIN RSA PRIVATE KEY-----").is_some());
    }

    #[test]
    fn blocks_openssh_private_key_header() {
        assert!(scan("-----BEGIN OPENSSH PRIVATE KEY-----").is_some());
    }

    #[test]
    fn blocks_bare_private_key_header() {
        assert!(scan("-----BEGIN PRIVATE KEY-----").is_some());
    }

    // --- Slack ---

    #[test]
    fn blocks_slack_bot_token() {
        // Synthetic token — real format is xoxb-<digits>-<alphanum>
        // Split across concat! so GitHub secret scanning does not flag it.
        let token = concat!("xoxb", "-111111111111-", "AAAAABBBBBCCCCC");
        assert!(scan(token).is_some());
    }

    // --- Stripe ---

    #[test]
    fn blocks_stripe_live_secret() {
        // Synthetic key — split so GitHub secret scanning does not flag it.
        let key = concat!("sk", "_live_", "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH");
        assert!(scan(key).is_some());
    }

    #[test]
    fn blocks_stripe_publishable() {
        let key = concat!("pk", "_live_", "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH");
        assert!(scan(key).is_some());
    }

    // --- .env style ---

    #[test]
    fn blocks_env_secret_assignment() {
        assert!(scan("SECRET=mysupersecretvalue123").is_some());
    }

    #[test]
    fn blocks_env_password_assignment() {
        assert!(scan("PASSWORD=hunter2password!").is_some());
    }

    #[test]
    fn blocks_env_api_key_assignment() {
        assert!(scan("API_KEY=abcdef1234567890abcdef").is_some());
    }

    // --- Bearer token ---

    #[test]
    fn blocks_bearer_token() {
        assert!(scan("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234").is_some());
    }

    // --- Clean text ---

    #[test]
    fn allows_clean_code() {
        assert!(scan("fn main() { println!(\"hello\"); }").is_none());
    }

    #[test]
    fn allows_git_sha() {
        // 40-char git SHA must not trigger (intentionally excluded pattern)
        assert!(scan("commit abc1234def5678901234567890abcdef12345678").is_none());
    }

    #[test]
    fn allows_empty() {
        assert!(scan("").is_none());
    }

    // ── v0.2 new secret patterns ──────────────────────────────────────────────

    #[test]
    fn blocks_anthropic_api_key() {
        let key =
            "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(scan(key).is_some());
    }

    #[test]
    fn blocks_openai_api_key() {
        let key = "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(scan(key).is_some());
    }

    #[test]
    fn blocks_huggingface_token() {
        let tok = "hf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(scan(tok).is_some());
    }

    #[test]
    fn blocks_gitlab_pat() {
        let tok = "glpat-AAAABBBBCCCCDDDDEEEE";
        assert!(scan(tok).is_some());
    }

    #[test]
    fn blocks_npm_token() {
        // npm_ + exactly 36 alphanumeric chars
        let tok = "npm_AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGH";
        assert!(scan(tok).is_some());
    }

    #[test]
    fn blocks_sendgrid_key() {
        let key = "SG.AAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(scan(key).is_some());
    }

    #[test]
    fn blocks_twilio_key() {
        // SK + exactly 32 hex chars — split so GitHub secret scanning does not flag it.
        let key = concat!("SK", "1234567890abcdef1234567890abcdef");
        assert!(scan(key).is_some());
    }

    #[test]
    fn blocks_db_conn_with_password() {
        assert!(scan("postgres://admin:supersecret@db.example.com/mydb").is_some());
    }
}
