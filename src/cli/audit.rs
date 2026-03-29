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
    println!(
        "{:<30} {:<25} {:<8} {:<20} RULE",
        "TIMESTAMP", "HOOK", "VERDICT", "USER@HOST"
    );
    println!("{}", "-".repeat(110));

    for line in &lines {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let ts = entry["ts"].as_str().unwrap_or("-");
            let hook = entry["hook"].as_str().unwrap_or("-");
            let verdict = entry["verdict"].as_str().unwrap_or("-");
            let rule = entry["rule"].as_str().unwrap_or("");
            let user = entry["user"].as_str().unwrap_or("");
            let host = entry["host"].as_str().unwrap_or("");

            let verdict_display = match verdict {
                "block" => format!("🚫 {}", verdict),
                "redact" => format!("✂️  {}", verdict),
                _ => format!("✅ {}", verdict),
            };
            let identity = if user.is_empty() && host.is_empty() {
                String::new()
            } else {
                format!("{}@{}", user, host)
            };

            println!(
                "{:<30} {:<25} {:<15} {:<20} {}",
                ts, hook, verdict_display, identity, rule
            );
        }
    }

    Ok(())
}

/// kiteguard audit verify — walks the hash-chain and reports any tampering.
/// Covers the live log AND all rotated archives (audit.log.1 – audit.log.3).
pub fn verify() -> Result<()> {
    let log_dir = crate::util::home_dir().join(".kiteguard");
    let live_log = log_dir.join("audit.log");

    if !live_log.exists() {
        println!("No audit log found.");
        return Ok(());
    }

    // Verify oldest archive first, then the live log.
    let mut log_files: Vec<std::path::PathBuf> = (1_u8..=3_u8)
        .rev()
        .map(|i| log_dir.join(format!("audit.log.{}", i)))
        .filter(|p| p.exists())
        .collect();
    log_files.push(live_log);

    let mut total_errors = 0usize;
    let mut total_entries = 0usize;

    for log_path in &log_files {
        let label = log_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let (entries, errors) = verify_file(log_path, &label)?;
        total_entries += entries;
        total_errors += errors;
    }

    if total_errors == 0 {
        println!(
            "\n✅ Chain verified — {} entries across {} file(s), no tampering detected.",
            total_entries,
            log_files.len()
        );
    } else {
        eprintln!(
            "\n❌ {} integrity error(s) detected across audit logs.",
            total_errors
        );
        std::process::exit(1);
    }

    Ok(())
}

fn verify_file(log_path: &std::path::Path, label: &str) -> Result<(usize, usize)> {
    let content = fs::read_to_string(log_path)?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        println!("[{}] empty — skipping", label);
        return Ok((0, 0));
    }

    println!("Verifying {} ({} entries)...", label, lines.len());

    let zeros = "0".repeat(64);
    let mut expected_prev = zeros;
    let mut expected_seq: Option<u64> = None; // None until first seq-bearing entry
    let mut last_ts = String::new();
    let mut errors = 0usize;

    for (i, line) in lines.iter().enumerate() {
        let entry: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("  [FAIL] entry {:>5}: invalid JSON", i + 1);
                errors += 1;
                continue;
            }
        };

        let stored_hash = entry["hash"].as_str().unwrap_or("").to_string();
        let stored_prev = entry["prev_hash"].as_str().unwrap_or("");

        // 1. Verify prev_hash linkage (chain continuity)
        if stored_prev != expected_prev {
            eprintln!(
                "  [FAIL] entry {:>5}: chain broken (prev_hash mismatch)",
                i + 1
            );
            errors += 1;
        }

        // 2. Reconstruct entry_body by stripping the trailing ,"hash":"<64hex>"}
        //    The hash field is always last and always 64 lowercase hex chars.
        let hash_suffix = format!(r#","hash":"{}"}}"#, stored_hash);
        let entry_body = match line.strip_suffix(&hash_suffix) {
            Some(prefix) => format!("{}}}", prefix),
            None => {
                eprintln!(
                    "  [FAIL] entry {:>5}: malformed (hash field not at end or wrong length)",
                    i + 1
                );
                errors += 1;
                expected_prev = stored_hash;
                continue;
            }
        };

        // 3. Verify the hash matches the entry body
        let computed_hash = crate::crypto::sha256_hex(entry_body.as_bytes());
        if computed_hash != stored_hash {
            eprintln!(
                "  [FAIL] entry {:>5}: hash mismatch — entry was modified after logging",
                i + 1
            );
            errors += 1;
        }

        // 4. Verify sequence number is strictly incrementing (if present)
        if let Some(seq) = entry["seq"].as_u64() {
            match expected_seq {
                Some(exp) if seq != exp => {
                    eprintln!(
                        "  [FAIL] entry {:>5}: sequence gap or reuse (expected seq {}, got {}) — possible replay or reorder attack",
                        i + 1, exp, seq
                    );
                    errors += 1;
                }
                _ => {}
            }
            expected_seq = Some(seq + 1);
        }

        // 5. Verify timestamps are non-decreasing (if present)
        let ts = entry["ts"].as_str().unwrap_or("");
        if !ts.is_empty() && !last_ts.is_empty() && ts < last_ts.as_str() {
            eprintln!(
                "  [FAIL] entry {:>5}: timestamp went backwards ({} < {}) — possible replay attack",
                i + 1, ts, last_ts
            );
            errors += 1;
        }
        if !ts.is_empty() {
            last_ts = ts.to_string();
        }

        expected_prev = stored_hash;
    }

    Ok((lines.len(), errors))
}
