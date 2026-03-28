use crate::engine::verdict::Verdict;
use crate::error::Result;
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

    let entry = format!(
        r#"{{"ts":"{}","hook":"{}","verdict":"{}","rule":"{}","input_hash":"{}"}}"#,
        crate::util::timestamp(),
        hook_event,
        verdict.as_str(),
        rule,
        hash_input(raw_input),
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    writeln!(file, "{}", entry)?;
    Ok(())
}

fn log_dir() -> std::path::PathBuf {
    crate::util::home_dir().join(".kiteguard")
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
