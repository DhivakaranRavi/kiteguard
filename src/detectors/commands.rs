use crate::engine::verdict::Verdict;
use regex::Regex;
use std::sync::OnceLock;

/// Maximum command length to protect against ReDoS on user-supplied patterns.
/// Inputs longer than this are truncated before matching.
const MAX_MATCH_LEN: usize = 4096;

static REDOS_CHECK: OnceLock<Regex> = OnceLock::new();

/// Returns true if the pattern contains constructs prone to catastrophic
/// backtracking: nested quantifiers like `(x+)+`, `(x*)*`, `(x|x)*`.
fn is_redos_risky(pattern: &str) -> bool {
    // Compiled once — previously this called Regex::new on every invocation.
    let risky = REDOS_CHECK.get_or_init(|| {
        Regex::new(r"[+*?}][)\]]\s*[+*?{]|\([^)]*[+*?]\s*\)[+*?]").unwrap()
    });
    risky.is_match(pattern)
}

/// Scans a bash command against configured block patterns.
pub fn scan(command: &str, patterns: &[String]) -> Option<Verdict> {
    // Truncate input to cap worst-case matching time on user patterns.
    let safe_input = if command.len() > MAX_MATCH_LEN {
        &command[..MAX_MATCH_LEN]
    } else {
        command
    };

    for pattern in patterns {
        if is_redos_risky(pattern) {
            eprintln!(
                "kiteguard: skipping potentially ReDoS-risky bash pattern: {:?}",
                pattern
            );
            continue;
        }
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(safe_input) {
                return Some(Verdict::block(
                    "dangerous_command",
                    format!("Blocked dangerous command pattern: `{}`", pattern),
                ));
            }
        }
    }
    None
}
