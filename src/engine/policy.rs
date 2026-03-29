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

    // Resolve symlinks before reading to prevent a crafted symlink from
    // redirecting policy reads to arbitrary filesystem paths.
    let resolved = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.clone());
    // config_dir() is expected to be something like ~/.config/kiteguard.
    // If the resolved path escapes that directory, refuse to load.
    if let Some(expected_dir) = config_path.parent() {
        if let Ok(canon_dir) = expected_dir.canonicalize() {
            if !resolved.starts_with(&canon_dir) {
                return Err(format!(
                    "rules.json resolves outside config directory ({}): refusing to load",
                    resolved.display()
                )
                .into());
            }
        }
    }

    // Atomically read file content.  Empty string = no custom config → use defaults.
    let raw_content = match std::fs::read_to_string(&resolved) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!("Failed to read config {}: {}", resolved.display(), e).into())
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
    // Important: validate with the (?i) prefix that commands.rs wraps them in,
    // so that inline-flag interactions (e.g. (?-i:...)) are caught here at load
    // time rather than silently failing in the hot path cache.
    for pattern in &policy.bash.block_patterns {
        regex::Regex::new(&format!("(?i){}", pattern)).map_err(|e| {
            format!(
                "Invalid regex in rules.json bash.block_patterns (with (?i) prefix): {:?}: {}",
                pattern, e
            )
        })?;
    }

    // Warn loudly if any protection module has been explicitly disabled so that
    // an accidental edit does not silently reduce the security posture.
    if !policy.bash.enabled {
        eprintln!("kiteguard: WARNING — bash protection is DISABLED in rules.json");
    }
    if !policy.injection.enabled {
        eprintln!("kiteguard: WARNING — injection protection is DISABLED in rules.json");
    }
    if !policy.pii.block_in_prompt {
        eprintln!("kiteguard: WARNING — PII prompt blocking is DISABLED in rules.json");
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
        // Two independent sentinels must both be absent for us to treat this as
        // "not yet signed" (first-run / pre-init).  An attacker trying to bypass
        // signing by deleting the key files would need to also delete BOTH:
        //   • .signature_required  — written at first sign (contains key material)
        //   • .key_fingerprint     — SHA-256 of the key, written at first sign
        //     (no key material, so there is no legitimate reason to delete it)
        // Requiring deletion of both files makes bypasses much harder to execute
        // without leaving obvious forensic traces.
        let sentinel = config_dir.join(".signature_required");
        let fingerprint = config_dir.join(".key_fingerprint");
        if sentinel.exists() || fingerprint.exists() {
            return Err(concat!(
                "POLICY INTEGRITY CHECK FAILED — signing key or signature file is missing.\n",
                "  This may indicate an attempt to bypass policy enforcement by deleting key files.\n",
                "  To restore: run 'kiteguard policy sign' to re-establish the signature.\n",
                "  All actions are blocked until the signature is restored (fail-closed)."
            ).into());
        }
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
