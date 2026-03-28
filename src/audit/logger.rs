use crate::engine::verdict::Verdict;
use crate::error::Result;
use std::fs::{self, OpenOptions};
use std::io::Write;

/// Rotate when the log exceeds 10 MB; keep up to 3 rotated files.
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;
const MAX_ROTATED: u8 = 3;

/// Appends a structured, hash-chained JSON event to ~/.kiteguard/audit.log.
///
/// Each entry contains:
/// - Identity: user, host, repo (for post-incident attribution)
/// - input_hash: SHA-256 of the raw prompt/tool payload (correlation without storing PII)
/// - prev_hash: SHA-256 of the previous entry body (hash-chain for tamper detection)
/// - hash: SHA-256 of this entry body (the chain link)
///
/// Tampering with any entry breaks all subsequent hashes. Verify with
/// `kiteguard audit verify`.
pub fn log(hook_event: &str, raw_input: &str, verdict: &Verdict) -> Result<()> {
    let log_dir = log_dir();
    fs::create_dir_all(&log_dir)?;

    // Ensure directory is owner-only even when created by the logger
    // (e.g. when a hook fires before `kiteguard init` runs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700));
    }

    let log_path = log_dir.join("audit.log");

    maybe_rotate(&log_path)?;

    let prev_hash = read_last_hash(&log_path);

    let rule = match verdict {
        Verdict::Block { rule, .. } => rule.as_str(),
        _ => "",
    };

    // Build the entry body — the string we will hash (no "hash" field yet).
    // json_str() ensures all values are properly JSON-escaped.
    let entry_body = format!(
        "{{\"ts\":{ts},\"hook\":{hook},\"verdict\":{verdict},\"rule\":{rule},\
\"user\":{user},\"host\":{host},\"repo\":{repo},\
\"input_hash\":\"{input_hash}\",\"prev_hash\":\"{prev_hash}\"}}",
        ts = json_str(&crate::util::timestamp()),
        hook = json_str(hook_event),
        verdict = json_str(verdict.as_str()),
        rule = json_str(rule),
        user = json_str(&identity::user()),
        host = json_str(&identity::host()),
        repo = json_str(&identity::repo()),
        input_hash = crate::crypto::sha256_hex(raw_input.as_bytes()),
        prev_hash = prev_hash,
    );

    // Hash the body and append it as the last field — this is the chain link.
    let hash = crate::crypto::sha256_hex(entry_body.as_bytes());
    let entry = format!(
        r#"{},"hash":"{}"}}"#,
        entry_body.strip_suffix('}').unwrap_or(&entry_body),
        hash
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // Keep the log file owner-only (chmod 600). This is a no-op on subsequent
    // opens; on first creation it overrides the process umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
    }

    writeln!(file, "{}", entry)?;
    Ok(())
}

fn log_dir() -> std::path::PathBuf {
    crate::util::home_dir().join(".kiteguard")
}

/// Reads the `hash` field from the last line of the log.
/// Returns 64 zeros for the genesis entry (no predecessor).
fn read_last_hash(log_path: &std::path::Path) -> String {
    let zeros = "0".repeat(64);
    let content = match fs::read_to_string(log_path) {
        Ok(s) => s,
        Err(_) => return zeros,
    };
    let last_line = match content.trim_end().lines().last() {
        Some(l) => l,
        None => return zeros,
    };
    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) {
        if let Some(h) = entry["hash"].as_str() {
            return h.to_string();
        }
    }
    zeros
}

/// Rotates the log when it exceeds MAX_LOG_SIZE.
/// Keeps audit.log.1, .2, .3 as rotated archives; drops oldest on overflow.
fn maybe_rotate(log_path: &std::path::Path) -> Result<()> {
    let size = match fs::metadata(log_path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(()), // file doesn't exist yet
    };
    if size < MAX_LOG_SIZE {
        return Ok(());
    }
    // Shift rotated files: .2 → .3, .1 → .2
    for i in (1..MAX_ROTATED).rev() {
        let from = log_path.with_extension(format!("log.{}", i));
        let to = log_path.with_extension(format!("log.{}", i + 1));
        if from.exists() {
            let _ = fs::rename(&from, &to);
        }
    }
    fs::rename(log_path, log_path.with_extension("log.1"))?;
    Ok(())
}

/// Wraps a string as a JSON string literal with proper escaping.
/// Returns `"value"` including the surrounding quotes.
fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

mod identity {
    /// Current OS username.
    pub fn user() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".into())
    }

    /// Machine hostname (tries $HOSTNAME, /etc/hostname, then `hostname` command).
    pub fn host() -> String {
        if let Ok(h) = std::env::var("HOSTNAME") {
            if !h.is_empty() {
                return h;
            }
        }
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let h = h.trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
        std::process::Command::new("hostname")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown".into())
    }

    /// Git repo root of the current working directory (best-effort).
    pub fn repo() -> String {
        std::process::Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
}
