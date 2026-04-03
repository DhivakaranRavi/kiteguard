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
    /// Optional semantic version tag for this policy (e.g. "1.2.0").
    /// Recorded in the audit log so operators can correlate events to policy revisions.
    pub version: Option<String>,
    /// Fetch policy JSON from this HTTPS URL on startup (org-wide policy distribution).
    /// Falls back to local rules.json when the fetch fails.
    pub remote_policy_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BashPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_bash_patterns")]
    pub block_patterns: Vec<String>,
    /// Commands that match any of these patterns are always allowed, even if they
    /// also match a block pattern. Checked before block_patterns.
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub block_on_error: bool,
}

#[derive(Debug, Deserialize)]
pub struct FilePathPolicy {
    #[serde(default = "default_block_read_paths")]
    pub block_read: Vec<String>,
    #[serde(default = "default_block_write_paths")]
    pub block_write: Vec<String>,
    /// Glob patterns that are always allowed even if they match a block_read pattern.
    #[serde(default)]
    pub allow_read: Vec<String>,
    /// Glob patterns that are always allowed even if they match a block_write pattern.
    #[serde(default)]
    pub allow_write: Vec<String>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct UrlPolicy {
    #[serde(default = "default_blocked_domains")]
    pub blocklist: Vec<String>,
    /// URL substrings or patterns that are always allowed regardless of blocklist.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct InjectionPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub token: Option<String>,
    /// HMAC-SHA256 signing secret. When set, every outbound webhook POST includes
    /// an `X-KiteGuard-Signature: sha256=<hex>` header so receivers can verify
    /// authenticity. Supports `$ENV_VAR` indirection.
    pub hmac_secret: Option<String>,
}

// ── Manual Default impls ─────────────────────────────────────────────────────
// These mirror every `#[serde(default = "...")]` annotation so that
// `Policy::default()` (and sub-struct defaults triggered by `#[serde(default)]`
// in the Policy struct) produce the same secure values as JSON deserialization.

impl Default for BashPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            block_patterns: default_bash_patterns(),
            allow_patterns: Vec::new(),
            block_on_error: true,
        }
    }
}

impl Default for FilePathPolicy {
    fn default() -> Self {
        Self {
            block_read: default_block_read_paths(),
            block_write: default_block_write_paths(),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
        }
    }
}

impl Default for PiiPolicy {
    fn default() -> Self {
        Self {
            block_in_prompt: true,
            block_in_file_content: true,
            redact_in_response: true,
            types: default_pii_types(),
        }
    }
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            blocklist: default_blocked_domains(),
            allowlist: Vec::new(),
        }
    }
}

impl Default for InjectionPolicy {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

fn default_bash_patterns() -> Vec<String> {
    vec![
        r"curl[^|]*\|[^|]*(bash|sh)".into(),
        r"wget[^|]*\|[^|]*(bash|sh)".into(),
        r"rm\s+-rf\s+/".into(),      // rm -rf /<anything>
        r"rm\s+-rf\s+~".into(),      // rm -rf ~/... and rm -rf ~/.ssh etc.
        r"rm\s+-rf\s+\$HOME".into(), // rm -rf $HOME/...
        r"eval\s*\(.*base64".into(),
        r"/dev/tcp/".into(),
        r"nc\s+-e\s+/bin".into(),
        r"chmod\s+777".into(),
        r">\s*/etc/".into(),
        r"crontab\s+-".into(),
        // ── v0.2 additions ──────────────────────────────────────────────────
        r"python3?\s+-c\s+.*exec\s*\(".into(), // python -c 'exec(...)'
        r"perl\s+-e\s+.{0,80}(system|exec|backtick|\.open)".into(), // perl one-liners
        r"mkfifo.*&&.*nc".into(),              // named pipe + netcat reverse shell
        r"bash\s+-i\s+>&?".into(),             // bash interactive reverse shell
        r"sh\s+-i\s+>&?".into(),               // sh interactive reverse shell
        r"dd\s+if=/dev/\w+\s+of=/dev/\w+".into(), // dd disk cloning
        r":\s*\(\s*\)\s*\{\s*:\|:".into(),     // fork bomb
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
        // Shell startup files — prevent reverse-shell persistence via profile injection
        "**/.bashrc".into(),
        "**/.bash_profile".into(),
        "**/.zshrc".into(),
        "**/.profile".into(),
        "**/.bash_logout".into(),
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
    // If KITEGUARD_POLICY_URL is set, try fetching org-wide policy first.
    // On any failure we fall through to local rules.json gracefully.
    if let Ok(remote_url) = std::env::var("KITEGUARD_POLICY_URL") {
        if !remote_url.is_empty() {
            if let Some(remote_json) = fetch_remote_policy(&remote_url) {
                match serde_json::from_str::<Policy>(&remote_json) {
                    Ok(p) => {
                        crate::vlog!("policy: loaded from remote URL {}", remote_url);
                        return Ok(p);
                    }
                    Err(e) => {
                        eprintln!(
                            "kiteguard: remote policy parse error ({}): {} — falling back to local policy",
                            remote_url, e
                        );
                    }
                }
            }
        }
    }

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
    // Policy::default() now correctly delegates to each sub-struct's manual
    // Default impl (which uses the same values as the serde default functions).
    let policy = if raw_content.is_empty() {
        Policy::default()
    } else {
        serde_json::from_str::<Policy>(&raw_content)
            .map_err(|e| format!("Failed to parse rules.json: {}", e))?
    };

    // Validate user-supplied bash block_patterns are compilable regexes.
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

    // Validate allowlist patterns with same (?i) prefix.
    for pattern in &policy.bash.allow_patterns {
        regex::Regex::new(&format!("(?i){}", pattern)).map_err(|e| {
            format!(
                "Invalid regex in rules.json bash.allow_patterns (with (?i) prefix): {:?}: {}",
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

/// Tries to fetch a remote policy from `url` using curl (best-effort).
/// Returns the raw JSON body on success, or None on any failure.
/// Uses a strict SSRF guard and enforces HTTPS.
pub fn fetch_remote_policy(url: &str) -> Option<String> {
    use crate::audit::webhook::is_ssrf_safe;

    if !url.starts_with("https://") {
        eprintln!("kiteguard: remote_policy_url must use HTTPS — skipping remote policy fetch");
        return None;
    }
    if !is_ssrf_safe(url) {
        eprintln!(
            "kiteguard: remote_policy_url blocked (SSRF protection): {} — using local policy",
            url
        );
        return None;
    }

    // Resolve curl to an absolute path (same logic as webhook.rs).
    let curl_path = [
        "/usr/bin/curl",
        "/usr/local/bin/curl",
        "/opt/homebrew/bin/curl",
        "/opt/local/bin/curl",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).exists())
    .copied()?;

    let output = std::process::Command::new(curl_path)
        .args([
            "--silent",
            "--max-time",
            "5", // 5-second total timeout
            "--connect-timeout",
            "3",
            "--max-filesize",
            "65536", // 64 KB max policy size
            "--proto",
            "=https", // enforce HTTPS at curl level
            "--tlsv1.2",
            "-L",
            url,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        eprintln!(
            "kiteguard: remote policy fetch failed (non-zero curl exit) — using local policy"
        );
        return None;
    }

    String::from_utf8(output.stdout).ok()
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
                "POLICY INTEGRITY CHECK FAILED.\n",
                "  Run 'kiteguard policy sign' to re-establish the policy signature.\n",
                "  All actions are blocked until the signature is restored (fail-closed)."
            )
            .into());
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
