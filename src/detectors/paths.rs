use crate::engine::verdict::Verdict;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Glob-to-regex cache: avoids recompiling the same pattern on every call.
static GLOB_CACHE: OnceLock<Mutex<HashMap<String, Option<regex::Regex>>>> = OnceLock::new();

/// Maximum entries in the glob cache to prevent unbounded memory growth.
const MAX_GLOB_CACHE: usize = 256;

/// Scans prompt text for any mention of a blocked path.
/// Extracts tokens that look like file paths (contain `/` or start with `~`)
/// and checks each against the blocked read patterns.
/// This catches prompts like "read ~/.ssh/id_rsa" before any tool is called.
pub fn scan_prompt(prompt: &str, block_read: &[String]) -> Option<Verdict> {
    // Extract whitespace/quote-delimited tokens that look like paths
    for token in
        prompt.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';'))
    {
        let token = token.trim_matches(|c: char| matches!(c, '.' | ','));
        if (token.contains('/') || token.starts_with('~'))
            && !token.is_empty()
            && matches_any(token, block_read)
        {
            return Some(Verdict::block(
                "blocked_path_in_prompt",
                format!("Prompt references a sensitive path: `{}`", token),
            ));
        }
    }
    None
}

/// Checks a file READ path against blocked path patterns.
pub fn scan_read(path: &str, block_patterns: &[String]) -> Option<Verdict> {
    if matches_any(path, block_patterns) {
        return Some(Verdict::block(
            "blocked_file_read",
            format!("Read of sensitive path blocked: `{}`", path),
        ));
    }
    None
}

/// Checks a file WRITE path against blocked path patterns.
pub fn scan_write(path: &str, block_patterns: &[String]) -> Option<Verdict> {
    if matches_any(path, block_patterns) {
        return Some(Verdict::block(
            "blocked_file_write",
            format!("Write to sensitive path blocked: `{}`", path),
        ));
    }
    None
}

fn matches_any(path: &str, patterns: &[String]) -> bool {
    let expanded = expand_home(path);

    // Canonicalize to resolve symlinks so `~/.kiteguard/link -> /etc/passwd`
    // doesn't bypass the `/etc/**` block.
    //
    // For non-existent paths (e.g. a new write target) `canonicalize` returns
    // ENOENT and the fallback would skip symlink resolution on the PARENT dirs,
    // enabling a bypass: symlink /tmp/safe -> /etc, then write /tmp/safe/cron.d/x.
    // Fix: for non-existent paths, canonicalize the deepest existing ancestor
    // and re-attach the remaining components.
    let canonical = canonicalize_best_effort(&expanded);

    for pattern in patterns {
        let expanded_pattern = expand_home(pattern);
        // Check both the literal path and the resolved canonical path
        if glob_match(&expanded_pattern, &expanded) || glob_match(&expanded_pattern, &canonical) {
            return true;
        }
    }
    false
}

/// Canonicalize a path, resolving as many symlinks as possible even when the
/// final component (or several trailing components) do not yet exist.
///
/// Algorithm: walk up from the full path until we find an ancestor that exists,
/// canonicalize that ancestor, then re-attach the remaining components.
/// This prevents symlink bypass via intermediate directory symlinks on write paths.
fn canonicalize_best_effort(path: &str) -> String {
    use std::path::{Component, Path, PathBuf};
    let p = Path::new(path);

    // Fast path: path exists → full canonicalization.
    if let Ok(c) = std::fs::canonicalize(p) {
        return c.to_string_lossy().to_string();
    }

    // Walk up until we find an existing ancestor.
    let mut ancestor = PathBuf::from(p);
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();

    loop {
        if let Ok(c) = std::fs::canonicalize(&ancestor) {
            // Re-attach the missing suffix.
            let mut result = c;
            for part in suffix.iter().rev() {
                result.push(part);
            }
            return result.to_string_lossy().to_string();
        }
        // Nothing useful — pop the last component.
        match ancestor.file_name() {
            Some(name) => {
                suffix.push(name.to_os_string());
                ancestor.pop();
            }
            None => break,
        }
        // Stop at filesystem root.
        if ancestor.components().count() == 0
            || ancestor
                .components()
                .all(|c| matches!(c, Component::RootDir))
        {
            break;
        }
    }

    // Absolute fallback: return original expanded path.
    path.to_string()
}

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        let home = crate::util::home_dir().to_string_lossy().to_string();
        path.replacen('~', &home, 1)
    } else {
        path.to_string()
    }
}

/// Simple glob matcher supporting `*`, `**`, and `?`.
/// Compiled regexes are cached per-process so the same pattern is never
/// compiled more than once (e.g. when matching against both the user-supplied
/// path and its canonicalized form).
fn glob_match(pattern: &str, path: &str) -> bool {
    let cache = GLOB_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    // Evict an arbitrary entry when the cache is full to cap memory usage.
    if map.len() >= MAX_GLOB_CACHE && !map.contains_key(pattern) {
        if let Some(key) = map.keys().next().cloned() {
            map.remove(&key);
        }
    }
    map.entry(pattern.to_string())
        .or_insert_with(|| {
            let s = glob_to_regex(pattern);
            regex::Regex::new(&s).ok()
        })
        .as_ref()
        .is_some_and(|re| re.is_match(path))
}

fn glob_to_regex(pattern: &str) -> String {
    let mut result = String::from("^");
    // Strip backslashes before converting — glob syntax has no escape sequences
    // (unlike regex). A user who writes `**/*\.env` intending a literal dot
    // would otherwise get a regex that requires a literal backslash in the
    // filename. Removing backslashes makes glob semantics unambiguous.
    let pattern: String = pattern.chars().filter(|&c| c != '\\').collect();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                result.push_str(".*");
                i += 2;
                if i < chars.len() && chars[i] == '/' {
                    i += 1;
                }
            }
            '*' => {
                result.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                result.push('.');
                i += 1;
            }
            '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' => {
                result.push('\\');
                result.push(chars[i]);
                i += 1;
            }
            c => {
                result.push(c);
                i += 1;
            }
        }
    }
    result.push('$');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- glob_to_regex / glob_match ---

    #[test]
    fn glob_star_star_matches_nested_path() {
        // ** should cross directory boundaries
        assert!(glob_match("**/.ssh/**", "/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn glob_single_star_does_not_cross_separator() {
        // * must not match /
        assert!(!glob_match("/etc/*", "/etc/sub/passwd"));
    }

    #[test]
    fn glob_question_mark_matches_single_char() {
        assert!(glob_match("/tmp/?.txt", "/tmp/a.txt"));
        assert!(!glob_match("/tmp/?.txt", "/tmp/ab.txt"));
    }

    #[test]
    fn glob_literal_dot_escaped() {
        // .env should not match aenv
        assert!(glob_match("**/.env", "/project/.env"));
        assert!(!glob_match("**/.env", "/project/aenv"));
    }

    // --- expand_home ---

    #[test]
    fn expand_home_tilde_slash() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(expand_home("~/foo"), format!("{}/foo", home));
    }

    #[test]
    fn expand_home_tilde_alone() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(expand_home("~"), home);
    }

    #[test]
    fn expand_home_no_tilde_unchanged() {
        assert_eq!(expand_home("/etc/passwd"), "/etc/passwd");
    }

    // --- scan_read ---

    #[test]
    fn blocks_ssh_dir_read() {
        let result = scan_read("/home/user/.ssh/id_rsa", &pats(&["**/.ssh/**"]));
        assert!(result.is_some());
    }

    #[test]
    fn allows_safe_path_read() {
        let result = scan_read("/home/user/project/main.rs", &pats(&["**/.ssh/**"]));
        assert!(result.is_none());
    }

    // --- scan_write ---

    #[test]
    fn blocks_etc_write() {
        let result = scan_write("/etc/hosts", &pats(&["/etc/**"]));
        assert!(result.is_some());
    }

    #[test]
    fn blocks_env_file_write() {
        let result = scan_write("/project/.env", &pats(&["**/.env"]));
        assert!(result.is_some());
    }

    #[test]
    fn allows_safe_path_write() {
        let result = scan_write("/project/src/main.rs", &pats(&["/etc/**", "**/.env"]));
        assert!(result.is_none());
    }

    // --- scan_prompt ---

    #[test]
    fn prompt_scan_catches_ssh_key_mention() {
        let result = scan_prompt("Please read ~/.ssh/id_rsa", &pats(&["**/.ssh/**"]));
        assert!(result.is_some());
    }

    #[test]
    fn prompt_scan_allows_safe_prompt() {
        let result = scan_prompt("Refactor the login function", &pats(&["**/.ssh/**"]));
        assert!(result.is_none());
    }

    // --- Glob cache eviction cap (M-1 fix) ---

    #[test]
    fn glob_cache_cap_does_not_panic_with_many_patterns() {
        // Feed more than MAX_GLOB_CACHE (256) unique patterns to exercise eviction.
        let patterns: Vec<String> = (0..300)
            .map(|i| format!("/unique/path/dir_{}", i))
            .collect();
        // Safe path must not match any of the block patterns.
        let result = scan_read("/safe/other/file.rs", &patterns);
        assert!(result.is_none());
        // A path matching the last pattern must still be blocked after eviction.
        let result = scan_read("/unique/path/dir_299", &patterns);
        assert!(result.is_some());
    }
}
