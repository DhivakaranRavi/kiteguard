use crate::error::Result;
use std::fs;

/// kiteguard audit — pretty prints the local audit log
pub fn run() -> Result<()> {
    let log_path = crate::util::home_dir().join(".kiteguard").join("audit.log");

    if !log_path.exists() {
        println!("No audit log found. Run `kiteguard init` and use Claude Code first.");
        return Ok(());
    }

    let content = fs::read_to_string(&log_path)?;
    let lines: Vec<&str> = content.lines().collect();

    println!("kiteguard audit log ({} events)\n", lines.len());
    println!("{:<30} {:<25} {:<8} RULE", "TIMESTAMP", "HOOK", "VERDICT");
    println!("{}", "-".repeat(90));

    for line in &lines {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let ts = entry["ts"].as_str().unwrap_or("-");
            let hook = entry["hook"].as_str().unwrap_or("-");
            let verdict = entry["verdict"].as_str().unwrap_or("-");
            let rule = entry["rule"].as_str().unwrap_or("");

            let verdict_display = match verdict {
                "block" => format!("🚫 {}", verdict),
                "redact" => format!("✂️  {}", verdict),
                _ => format!("✅ {}", verdict),
            };

            println!("{:<30} {:<25} {:<15} {}", ts, hook, verdict_display, rule);
        }
    }

    Ok(())
}
