use crate::engine::verdict::Verdict;
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;

/// Appends a structured JSON event to ~/.kiteguard/audit.log
pub fn log(hook_event: &str, raw_input: &str, verdict: &Verdict) -> Result<()> {
    let log_dir = log_dir();
    fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("audit.log");

    let rule = match verdict {
        Verdict::Block { rule, .. } => rule.as_str(),
        _ => "",
    };

    let entry = json!({
        "ts":       Utc::now().to_rfc3339(),
        "hook":     hook_event,
        "verdict":  verdict.as_str(),
        "rule":     rule,
        "input_hash": hash_input(raw_input),
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    writeln!(file, "{}", entry)?;
    Ok(())
}

fn log_dir() -> std::path::PathBuf {
    dirs::home_dir().unwrap_or_default().join(".kiteguard")
}

/// Hash the raw input so we don't store prompt content in audit log.
/// Provides correlation without logging potentially sensitive data.
fn hash_input(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
