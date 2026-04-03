use std::path::PathBuf;

/// Verbose tracing macro — writes to stderr AND ~/.kiteguard/verbose.log when KITEGUARD_VERBOSE=1.
/// Gemini CLI swallows hook stderr, so logging to a file lets you `tail -f` the trace live.
/// Output never goes to stdout (reserved for Gemini CLI JSON responses).
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if std::env::var("KITEGUARD_VERBOSE").as_deref() == Ok("1") {
            let msg = format!($($arg)*);
            // Strip ASCII control characters to prevent terminal escape injection
            // from attacker-controlled prompt/path content in verbose output.
            let msg: String = msg.chars()
                .map(|c| if c.is_ascii_control() && c != '\t' { '?' } else { c })
                .collect();
            eprintln!("\x1b[2m[kiteguard:trace]\x1b[0m {}", msg);
            // Also append to ~/.kiteguard/verbose.log so runtimes that swallow
            // hook stderr (e.g. Gemini CLI) can still be inspected via:
            //   tail -f ~/.kiteguard/verbose.log
            if let Ok(home) = std::env::var("HOME") {
                // Validate $HOME before using it as a path base (M-3).
                // Use an `if` guard rather than `return` so the macro compiles
                // in functions with any return type.
                let home_ok = !home.is_empty()
                    && std::path::Path::new(&home).is_absolute()
                    && !home.contains("..");
                if home_ok {
                let log_path = std::path::Path::new(&home)
                    .join(".kiteguard")
                    .join("verbose.log");
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                {
                    let _ = writeln!(f, "[kiteguard:trace] {}", msg);
                    // Restrict to owner-only — verbose log may contain prompt
                    // fragments that include PII or secrets.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &log_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
                } // end home_ok
            }
        }
    };
}

/// Returns the user's home directory using the HOME environment variable.
/// Exits if HOME is unset, empty, not absolute, or contains `..` components
/// — falling back to cwd would silently write config/logs into an
/// attacker-controlled directory (M-3: path-traversal via env var).
pub fn home_dir() -> PathBuf {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => {
            let p = PathBuf::from(&h);
            if !p.is_absolute() || h.contains("..") {
                eprintln!(
                    "kiteguard: fatal — HOME environment variable contains an unsafe path: {:?}",
                    h
                );
                std::process::exit(1);
            }
            p
        }
        _ => {
            eprintln!("kiteguard: fatal — HOME environment variable is not set");
            std::process::exit(1);
        }
    }
}

/// Returns a UTC timestamp string in ISO 8601 format using only std.
pub fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_iso8601(secs)
}

fn unix_to_iso8601(secs: u64) -> String {
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let mut days = secs / 86400;

    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days: [u64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &d in &month_days {
        if days < d {
            break;
        }
        days -= d;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
