use crate::error::Result;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub bash: BashPolicy,
    #[serde(default)]
    pub file_paths: FilePathPolicy,
    #[serde(default)]
    pub pii: PiiPolicy,
    #[serde(default)]
    pub urls: UrlPolicy,
    #[serde(default)]
    pub injection: InjectionPolicy,
    pub webhook: Option<WebhookConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BashPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_bash_patterns")]
    pub block_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub block_on_error: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct FilePathPolicy {
    #[serde(default = "default_block_read_paths")]
    pub block_read: Vec<String>,
    #[serde(default = "default_block_write_paths")]
    pub block_write: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PiiPolicy {
    #[serde(default = "default_true")]
    pub block_in_prompt: bool,
    #[serde(default = "default_true")]
    pub block_in_file_content: bool,
    #[serde(default = "default_true")]
    pub redact_in_response: bool,
    #[serde(default = "default_pii_types")]
    pub types: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UrlPolicy {
    #[serde(default = "default_blocked_domains")]
    pub blocklist: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct InjectionPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub token: Option<String>,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

fn default_bash_patterns() -> Vec<String> {
    vec![
        r"curl[^|]*\|[^|]*(bash|sh)".into(),
        r"wget[^|]*\|[^|]*(bash|sh)".into(),
        r"rm\s+-rf\s+/".into(),
        r"eval\s*\(.*base64".into(),
        r"/dev/tcp/".into(),
        r"nc\s+-e\s+/bin".into(),
        r"chmod\s+777".into(),
        r">\s*/etc/".into(),
        r"crontab\s+-".into(),
    ]
}

fn default_block_read_paths() -> Vec<String> {
    vec![
        "**/.ssh/**".into(),
        "**/.aws/credentials".into(),
        "**/.gnupg/**".into(),
        "**/.env".into(),
        "**/secrets/**".into(),
        "**/id_rsa".into(),
        "**/id_ed25519".into(),
    ]
}

fn default_block_write_paths() -> Vec<String> {
    vec![
        "**/.claude/settings.json".into(), // self-protection
        "/etc/**".into(),
        "**/.ssh/**".into(),
        "**/.aws/credentials".into(),
        "**/cron*".into(),
    ]
}

fn default_pii_types() -> Vec<String> {
    vec![
        "ssn".into(),
        "credit_card".into(),
        "email".into(),
        "phone".into(),
    ]
}

fn default_blocked_domains() -> Vec<String> {
    vec![
        "169.254.169.254".into(), // AWS/GCP metadata SSRF
        "metadata.google.internal".into(),
        "metadata.azure.com".into(),
    ]
}

// ── Loader ───────────────────────────────────────────────────────────────────

pub fn load() -> Result<Policy> {
    let config_path = config_path();

    // Atomically read file content.  Empty string = no custom config → use defaults.
    let raw_content = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!("Failed to read config {}: {}", config_path.display(), e).into())
        }
    };

    // Verify HMAC signature if key and signature file exist.
    // If sig is present but invalid → fail-closed (return Err).
    verify_policy_signature(&raw_content)?;

    // Parse from content, or fall back to secure built-in defaults.
    let policy = if raw_content.is_empty() {
        Policy::default()
    } else {
        serde_json::from_str::<Policy>(&raw_content)
            .map_err(|e| format!("Failed to parse rules.json: {}", e))?
    };

    // Validate user-supplied bash patterns are compilable regexes.
    // Warn and skip invalid ones rather than refusing to start — a single
    // bad pattern shouldn't disable all other protections.
    for pattern in &policy.bash.block_patterns {
        if regex::Regex::new(pattern).is_err() {
            eprintln!(
                "kiteguard: WARNING — invalid regex in rules.json bash.block_patterns: {:?} (skipping)",
                pattern
            );
        }
    }

    Ok(policy)
}

/// Verifies the HMAC-SHA256 signature over `raw_content`.
/// Skipped silently when no key/sig files exist (pre-init).
/// Returns Err (and blocks fail-closed) if the signature doesn't match.
fn verify_policy_signature(raw_content: &str) -> Result<()> {
    let config_dir = crate::util::home_dir().join(".kiteguard");
    let key_path = config_dir.join(".key");
    let sig_path = config_dir.join("policy.sig");

    if !key_path.exists() || !sig_path.exists() {
        return Ok(()); // Not yet signed — first run or pre-init
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .map_err(|e| format!("Failed to read policy key: {}", e))?;
    let expected_sig = std::fs::read_to_string(&sig_path)
        .map_err(|e| format!("Failed to read policy.sig: {}", e))?;
    let key = crate::crypto::hex_to_bytes(key_hex.trim())
        .ok_or("Policy key file is corrupted (invalid hex)")?;

    if !crate::crypto::hmac_verify(&key, raw_content.as_bytes(), expected_sig.trim()) {
        return Err(concat!(
            "POLICY INTEGRITY CHECK FAILED — rules.json may have been tampered with.\n",
            "  Run 'kiteguard policy sign' to re-sign after intentional changes.\n",
            "  All actions are blocked until the signature is restored (fail-closed)."
        )
        .into());
    }

    Ok(())
}

pub fn config_path() -> PathBuf {
    crate::util::home_dir()
        .join(".kiteguard")
        .join("rules.json")
}
