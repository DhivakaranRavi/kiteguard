use crate::engine::verdict::Verdict;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Glob-to-regex cache: avoids recompiling the same pattern on every call.
static GLOB_CACHE: OnceLock<Mutex<HashMap<String, Option<regex::Regex>>>> = OnceLock::new();

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
