use crate::engine::verdict::Verdict;
use crate::error::Result;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

// Serializes concurrent log writes within a single process.
// Prevents two simultaneous hook invocations (e.g. PostToolUse racing with Stop)
// from reading the same prev_hash and producing a broken chain link (L5).
static LOG_MUTEX: Mutex<()> = Mutex::new(());

// Active policy version tag — set once after policy load, read on every log write.
static POLICY_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Records the active policy version so it can be embedded in every audit entry.
/// Call this once after `policy::load()` in the hook entrypoint.
pub fn set_policy_version(v: &str) {
    let _ = POLICY_VERSION.set(v.to_string());
}

fn policy_version() -> &'static str {
    POLICY_VERSION.get().map(|s| s.as_str()).unwrap_or("")
}

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
pub fn log(hook_event: &str, raw_input: &str, verdict: &Verdict, client: &str) -> Result<()> {
    let log_dir = log_dir();
    fs::create_dir_all(&log_dir)?;

    // Ensure directory is owner-only even when created by the logger
    // (e.g. when a hook fires before `kiteguard init` runs).
    // Warn prominently on failure — a silent ignore could leave the audit log
    // world-readable (e.g. on a shared filesystem with a permissive umask).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700)) {
            eprintln!(
                "kiteguard: WARNING — could not restrict audit log directory permissions ({}): {}. \
Audit log may be readable by other local users.",
                log_dir.display(), e
            );
        }
    }

    let log_path = log_dir.join("audit.log");

    // Serialize all writes within the process to maintain the hash chain.
    // Without this lock, two concurrent hook invocations read the same prev_hash
    // and produce duplicate chain links, breaking 'kiteguard audit verify'.
    let _lock = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    maybe_rotate(&log_path)?;

    let prev_hash = read_last_hash(&log_path);
    let seq = read_last_seq(&log_path) + 1;

    let rule = match verdict {
        Verdict::Block { rule, .. } => rule.as_str(),
        _ => "",
    };
    let reason = match verdict {
        Verdict::Block { reason, .. } => reason.as_str(),
        _ => "",
    };

    // Build the entry body — the string we will hash (no "hash" field yet).
    // Use serde_json to guarantee proper escaping and single-line output.
    let body_value = serde_json::json!({
        "ts":             crate::util::timestamp(),
        "seq":            seq,
        "client":         client,
        "hook":           hook_event,
        "verdict":        verdict.as_str(),
        "rule":           rule,
        "reason":         reason,
        "policy_version": policy_version(),
        "user":           identity::user(),
        "host":           identity::host(),
        "repo":           identity::repo(),
        "input_hash":     crate::crypto::sha256_hex(raw_input.as_bytes()),
        "tokens_in":      estimate_tokens(raw_input),
        "prev_hash":      prev_hash,
    });
    let entry_body = serde_json::to_string(&body_value)
        .map_err(|e| format!("audit log serialization error: {}", e))?;

    // Hash the body and append it as the last field — this is the chain link.
    let hash = crate::crypto::sha256_hex(entry_body.as_bytes());
    let mut full_value: serde_json::Value =
        serde_json::from_str(&entry_body).map_err(|e| format!("audit log parse error: {}", e))?;
    full_value["hash"] = serde_json::Value::String(hash);
    let entry = serde_json::to_string(&full_value)
        .map_err(|e| format!("audit log serialization error: {}", e))?;

    // Open with mode 0o600 at creation time to eliminate the TOCTOU window
    // between file creation and a subsequent set_permissions call (L-1 fix).
    // On non-Unix the fallback omits the mode; permissions are still set below.
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&log_path)?
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?
        }
    };

    // Belt-and-suspenders: also call set_permissions so pre-existing log files
    // created before this fix are tightened up on the next write.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!(
                "kiteguard: WARNING — could not restrict audit log file permissions ({}): {}. \
Audit log may be readable by other local users.",
                log_path.display(),
                e
            );
        }
    }

    writeln!(file, "{}", entry)?;

    // Update the O(1) sidecar so the next invocation skips the full-file read.
    let sidecar = log_path.with_extension("log.tail");
    let _ = fs::write(&sidecar, &entry);
    // Restrict sidecar to owner-only — it contains a full audit entry with
    // identity metadata and must have the same protection as the main log.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "kiteguard: WARNING — could not restrict sidecar permissions ({}): {}. \
Audit sidecar may be readable by other local users.",
                sidecar.display(),
                e
            );
        }
    }

    Ok(())
}

fn log_dir() -> std::path::PathBuf {
    crate::util::home_dir().join(".kiteguard")
}

/// Reads the `hash` field from the last line of the log.
/// Returns 64 zeros for the genesis entry (no predecessor).
/// Uses a sidecar file `audit.log.tail` when present to avoid O(n) reads.
fn read_last_hash(log_path: &std::path::Path) -> String {
    let zeros = "0".repeat(64);
    // Fast path: read the sidecar file (written on every append).
    let sidecar = log_path.with_extension("log.tail");
    if let Ok(s) = fs::read_to_string(&sidecar) {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(s.trim()) {
            if let Some(h) = entry["hash"].as_str() {
                return h.to_string();
            }
        }
    }
    // Slow path: sidecar missing → read full log (legacy or first run).
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
    // The last entry is malformed or missing the hash field — chain reset.
    eprintln!(
        "kiteguard: WARNING — last audit log entry is malformed or missing 'hash' field; \
hash chain reset to genesis. Run 'kiteguard audit verify' to check log integrity."
    );
    zeros
}

/// Reads the `seq` field from the last line of the log.
/// Returns 0 if the file is empty, missing, or has no seq field (legacy entries).
/// Uses the same sidecar file as `read_last_hash` for O(1) access.
fn read_last_seq(log_path: &std::path::Path) -> u64 {
    let sidecar = log_path.with_extension("log.tail");
    if let Ok(s) = fs::read_to_string(&sidecar) {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(s.trim()) {
            if let Some(n) = entry["seq"].as_u64() {
                return n;
            }
        }
    }
    // Slow path.
    let content = match fs::read_to_string(log_path) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let last_line = match content.trim_end().lines().last() {
        Some(l) => l,
        None => return 0,
    };
    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) {
        if let Some(n) = entry["seq"].as_u64() {
            return n;
        }
    }
    0
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
        // Use absolute path to avoid PATH-hijacking attacks.
        // On macOS the binary is /bin/hostname; on Linux /usr/bin/hostname.
        let hostname_bin = if std::path::Path::new("/bin/hostname").exists() {
            "/bin/hostname"
        } else {
            "/usr/bin/hostname"
        };
        std::process::Command::new(hostname_bin)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown".into())
    }

    /// Git repo root of the current working directory (best-effort).
    pub fn repo() -> String {
        // Prefer the project directory set by the active CLI runtime — avoids a subprocess.
        for var in &["GEMINI_PROJECT_DIR", "CLAUDE_PROJECT_DIR"] {
            if let Ok(dir) = std::env::var(var) {
                if !dir.is_empty() {
                    return dir;
                }
            }
        }
        // Fall back to git rev-parse for Claude Code and VS Code Copilot.
        let git_bin = if std::path::Path::new("/usr/bin/git").exists() {
            "/usr/bin/git"
        } else if std::path::Path::new("/usr/local/bin/git").exists() {
            "/usr/local/bin/git"
        } else {
            // Cannot locate git at a known absolute path — skip rather than
            // fall back to a PATH-relative lookup that could be hijacked.
            return String::new();
        };
        std::process::Command::new(git_bin)
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
}

// Public re-exports so other modules (e.g. webhook.rs) can reuse the same
// identity resolution without duplicating logic.
pub fn identity_user() -> String {
    identity::user()
}
pub fn identity_host() -> String {
    identity::host()
}
pub fn identity_repo() -> String {
    identity::repo()
}

/// Rough token count estimate: 1 token ≈ 4 characters (GPT/Claude typical).
/// Stored in audit log for cost tracking and session analytics.
fn estimate_tokens(text: &str) -> u32 {
    // div_ceil equivalent compatible with MSRV 1.75
    // (div_ceil stabilised on integers in 1.73 but clippy recommends it from 1.73+;
    // we use it directly since 1.73 ≤ 1.75 MSRV)
    text.len().div_ceil(4) as u32
}
