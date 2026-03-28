use crate::engine::verdict::Verdict;

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
    for pattern in patterns {
        let expanded_pattern = expand_home(pattern);
        if glob_match(&expanded_pattern, &expanded) {
            return true;
        }
    }
    false
}

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        let home = dirs::home_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        path.replacen('~', &home, 1)
    } else {
        path.to_string()
    }
}

/// Simple glob matcher supporting `*`, `**`, and `?`.
fn glob_match(pattern: &str, path: &str) -> bool {
    // Use the glob crate pattern via simple matching
    // Convert glob to regex for matching
    let regex_str = glob_to_regex(pattern);
    regex::Regex::new(&regex_str)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn glob_to_regex(pattern: &str) -> String {
    let mut result = String::from("^");
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
            '*' => { result.push_str("[^/]*"); i += 1; }
            '?' => { result.push('.'); i += 1; }
            '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' => {
                result.push('\\');
                result.push(chars[i]);
                i += 1;
            }
            c => { result.push(c); i += 1; }
        }
    }
    result.push('$');
    result
}
