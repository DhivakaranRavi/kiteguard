use crate::engine::verdict::Verdict;
use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Maximum command length to protect against ReDoS on user-supplied patterns.
/// Inputs longer than this are truncated before matching.
const MAX_MATCH_LEN: usize = 4096;

static REDOS_CHECK: OnceLock<Regex> = OnceLock::new();

// Cache of compiled bash regexes keyed by pattern string.
// Avoids recompiling the same user-configured patterns on every hook invocation.
static BASH_CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();

/// Returns true if the pattern contains constructs prone to catastrophic
/// backtracking: nested quantifiers like `(x+)+`, `(x*)*`, `(x|x)*`.
fn is_redos_risky(pattern: &str) -> bool {
    // Compiled once — previously this called Regex::new on every invocation.
    // (?i) ensures uppercase quantifiers like `X+)+` are also caught.
    let risky = REDOS_CHECK
        .get_or_init(|| Regex::new(r"(?i)[+*?}][)\]]\s*[+*?{]|\([^)]*[+*?]\s*\)[+*?]").unwrap());
    risky.is_match(pattern)
}

/// Returns a compiled regex for the pattern, using a process-lifetime cache.
/// Returns `None` if the pattern is ReDoS-risky or invalid.
fn cached_bash_regex(pattern: &str) -> Option<Regex> {
    let cache = BASH_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(maybe_re) = guard.get(pattern) {
        return maybe_re.clone();
    }
    if is_redos_risky(pattern) {
        eprintln!(
            "kiteguard: skipping potentially ReDoS-risky bash pattern: {:?}",
            pattern
        );
        guard.insert(pattern.to_string(), None);
        return None;
    }
    let re = Regex::new(&format!("(?i){}", pattern)).ok();
    guard.insert(pattern.to_string(), re.clone());
    re
}

/// Scans a bash command against configured block patterns.
pub fn scan(command: &str, patterns: &[String]) -> Option<Verdict> {
    // Truncate at a safe UTF-8 char boundary to avoid panicking when byte index
    // MAX_MATCH_LEN falls inside a multi-byte character.  Without this, a crafted
    // payload with a 2-4 byte char at position 4096 panics the process (exit 101),
    // bypassing the fail-closed guard in main.rs.
    let safe_input = if command.len() > MAX_MATCH_LEN {
        let boundary = command.floor_char_boundary(MAX_MATCH_LEN);
        &command[..boundary]
    } else {
        command
    };

    for pattern in patterns {
        if let Some(re) = cached_bash_regex(pattern) {
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
