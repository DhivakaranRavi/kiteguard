use crate::engine::verdict::Verdict;
use regex::Regex;

/// Scans a bash command against configured block patterns.
pub fn scan(command: &str, patterns: &[String]) -> Option<Verdict> {
    for pattern in patterns {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(command) {
                return Some(Verdict::block(
                    "dangerous_command",
                    format!("Blocked dangerous command pattern: `{}`", pattern),
                ));
            }
        }
    }
    None
}
