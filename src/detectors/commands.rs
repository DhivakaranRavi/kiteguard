use crate::engine::verdict::Verdict;
use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Maximum command length to protect against ReDoS on user-supplied patterns.
/// Inputs longer than this are truncated before matching.
const MAX_MATCH_LEN: usize = 4096;

/// Overlap between consecutive scan windows so a match straddling a boundary is still seen.
const WINDOW_OVERLAP: usize = 512;

/// Maximum number of compiled regex entries to keep in the bash pattern cache.
/// Prevents unbounded memory growth if rules.json contains many unique patterns.
const MAX_BASH_CACHE: usize = 512;

static REDOS_CHECK: OnceLock<Regex> = OnceLock::new();

// Cache of compiled bash regexes keyed by pattern string.
// Avoids recompiling the same user-configured patterns on every hook invocation.
static BASH_CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();

/// Returns true if the pattern contains constructs prone to catastrophic
/// backtracking: nested quantifiers like `(x+)+`, `(x*)*`, `(x|x)*`.
fn is_redos_risky(pattern: &str) -> bool {
    // Compiled once — previously this called Regex::new on every invocation.
    // (?i) ensures uppercase quantifiers like `X+)+` are also caught.
    let risky = REDOS_CHECK.get_or_init(|| {
        Regex::new(r"(?i)[+*?}][)\]]\s*[+*?{]|\([^)]*[+*?]\s*\)[+*?]|\([^)]*\|[^)]*\)[+*?]")
            .unwrap()
    });
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
    // Evict an arbitrary entry when the cache is full to prevent unbounded
    // memory growth from attacker-controlled rules.json with many patterns.
    if guard.len() >= MAX_BASH_CACHE {
        if let Some(key) = guard.keys().next().cloned() {
            guard.remove(&key);
        }
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
    // Scan the whole command in overlapping MAX_MATCH_LEN windows. Truncating to
    // the first window would let an attacker pad the command so the payload sits
    // past the cut-off. Windows start/end on UTF-8 char boundaries (floor_char_boundary
    // is not available at our MSRV).
    let mut start = 0;
    loop {
        let mut end = (start + MAX_MATCH_LEN).min(command.len());
        while !command.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(v) = scan_window(&command[start..end], patterns) {
            return Some(v);
        }
        if end >= command.len() {
            return None;
        }
        let mut next = end.saturating_sub(WINDOW_OVERLAP);
        while !command.is_char_boundary(next) {
            next += 1;
        }
        start = next.max(start + 1);
        while !command.is_char_boundary(start) {
            start += 1;
        }
    }
}

fn scan_window(safe_input: &str, patterns: &[String]) -> Option<Verdict> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn is_redos_risky_pub(pattern: &str) -> bool {
        is_redos_risky(pattern)
    }

    // --- ReDoS detection ---

    #[test]
    fn redos_nested_plus_plus_caught() {
        assert!(is_redos_risky_pub(r"(x+)+"));
    }

    #[test]
    fn redos_nested_star_star_caught() {
        assert!(is_redos_risky_pub(r"(x*)*"));
    }

    #[test]
    fn redos_alternation_star_caught() {
        assert!(is_redos_risky_pub(r"(a|a)*"));
    }

    #[test]
    fn safe_pattern_not_flagged() {
        assert!(!is_redos_risky_pub(r"rm\s+-rf"));
    }

    // --- scan() ---

    #[test]
    fn matches_rm_rf() {
        let result = scan("rm -rf /", &pats(&[r"rm\s+-rf"]));
        assert!(result.is_some());
        assert!(result.unwrap().is_block());
    }

    #[test]
    fn case_insensitive_match() {
        let result = scan("RM -RF /", &pats(&[r"rm\s+-rf"]));
        assert!(result.is_some());
    }

    #[test]
    fn safe_command_not_blocked() {
        let result = scan("ls -la", &pats(&[r"rm\s+-rf"]));
        assert!(result.is_none());
    }

    #[test]
    fn matches_eval_base64() {
        let result = scan(
            "eval $(echo aGVsbG8= | base64 -d)",
            &pats(&[r"eval.*base64"]),
        );
        assert!(result.is_some());
    }

    #[test]
    fn redos_risky_pattern_skipped_does_not_panic() {
        // A ReDoS-risky pattern must be silently skipped, not crash
        let result = scan("aaaa", &pats(&[r"(a+)+b"]));
        assert!(result.is_none());
    }

    #[test]
    fn oversized_input_truncated_and_safe() {
        // Input > MAX_MATCH_LEN (4096) must not panic even if truncation
        // falls on a multi-byte UTF-8 boundary
        let big = "a".repeat(5000) + "🔥" + &"b".repeat(100);
        let result = scan(&big, &pats(&[r"rm\s+-rf"]));
        assert!(result.is_none());
    }

    #[test]
    fn payload_after_padding_is_still_caught() {
        let cmd = format!("echo ok;{}rm -rf /home/u", " ".repeat(5000));
        assert!(scan(&cmd, &pats(&[r"rm\s+-rf"])).is_some());
    }

    #[test]
    fn payload_straddling_window_boundary_is_caught() {
        let cmd = format!(
            "{}rm -rf /x{}",
            "a".repeat(MAX_MATCH_LEN - 4),
            "b".repeat(2000)
        );
        assert!(scan(&cmd, &pats(&[r"rm\s+-rf"])).is_some());
    }

    #[test]
    fn empty_patterns_always_allow() {
        let result = scan("rm -rf /", &[]);
        assert!(result.is_none());
    }

    // --- Cache eviction cap (M-1 fix) ---

    #[test]
    fn cache_cap_does_not_panic_with_many_patterns() {
        // Feed more than MAX_BASH_CACHE (512) unique patterns to exercise eviction.
        // None match the input so result is None — verifying no panic is the goal.
        let patterns: Vec<String> = (0..600)
            .map(|i| format!("never_matches_xyz_{}", i))
            .collect();
        let result = scan("safe command", &patterns);
        assert!(result.is_none());
        // Check matching still works after cache eviction pressure.
        let last_pat = vec!["safe command".to_string()];
        let result = scan("safe command", &last_pat);
        assert!(result.is_some());
    }
}
