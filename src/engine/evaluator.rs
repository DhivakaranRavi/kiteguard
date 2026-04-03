use crate::detectors::{commands, injection, paths, pii, secrets, urls};
use crate::engine::{policy::Policy, verdict::Verdict};
use regex::Regex;

/// Returns true if `text` matches any of the allowlist patterns.
/// An allowlist match short-circuits all block detectors — explicit allow wins.
fn is_explicitly_allowed(text: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if Regex::new(&format!("(?i){}", pattern))
            .ok()
            .map(|re| re.is_match(text))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Evaluate a developer's prompt (UserPromptSubmit)
pub fn evaluate_prompt(prompt: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:prompt ({} chars)", prompt.len());
    // Check if the prompt text itself references a blocked path
    crate::vlog!(
        "    detector:blocked_path_in_prompt ({} patterns)",
        policy.file_paths.block_read.len()
    );
    if let Some(v) = paths::scan_prompt(prompt, &policy.file_paths.block_read) {
        crate::vlog!("    ✗ BLOCKED by blocked_path_in_prompt");
        return v;
    }
    // Check if the prompt contains a dangerous bash command pattern
    if policy.bash.enabled {
        crate::vlog!(
            "    detector:bash_patterns_in_prompt ({} patterns)",
            policy.bash.block_patterns.len()
        );
        if let Some(v) = commands::scan(prompt, &policy.bash.block_patterns) {
            crate::vlog!("    ✗ BLOCKED by bash_patterns_in_prompt");
            return v;
        }
    }
    // Check if the prompt mentions a blocked URL (SSRF, blocklisted domains)
    crate::vlog!(
        "    detector:url_in_prompt ({} entries)",
        policy.urls.blocklist.len()
    );
    if let Some(v) = urls::scan_prompt(prompt, &policy.urls.blocklist) {
        crate::vlog!("    ✗ BLOCKED by url_in_prompt");
        return v;
    }
    if policy.injection.enabled {
        crate::vlog!("    detector:injection");
        if let Some(v) = injection::scan(prompt) {
            crate::vlog!("    ✗ BLOCKED by injection");
            return v;
        }
    }
    if policy.pii.block_in_prompt {
        crate::vlog!("    detector:pii ({} types)", policy.pii.types.len());
        if let Some(v) = pii::scan(prompt, &policy.pii.types) {
            crate::vlog!("    ✗ BLOCKED by pii");
            return v;
        }
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate a bash command (PreToolUse → Bash)
pub fn evaluate_command(command: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:command {:?}", command);
    if policy.bash.enabled {
        // Allowlist wins over blocklist — check first.
        if !policy.bash.allow_patterns.is_empty()
            && is_explicitly_allowed(command, &policy.bash.allow_patterns)
        {
            crate::vlog!("    ✓ allow (allowlist match)");
            return Verdict::Allow;
        }
        crate::vlog!(
            "    detector:bash_patterns ({} patterns)",
            policy.bash.block_patterns.len()
        );
        if let Some(v) = commands::scan(command, &policy.bash.block_patterns) {
            crate::vlog!("    ✗ BLOCKED by bash_patterns");
            return v;
        }
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate a file read path (PreToolUse → Read)
pub fn evaluate_file_read(path: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:read_path {:?}", path);
    if !policy.file_paths.allow_read.is_empty()
        && paths::is_glob_allowed(path, &policy.file_paths.allow_read)
    {
        crate::vlog!("    ✓ allow (allow_read match)");
        return Verdict::Allow;
    }
    crate::vlog!(
        "    detector:blocked_file_read ({} patterns)",
        policy.file_paths.block_read.len()
    );
    if let Some(v) = paths::scan_read(path, &policy.file_paths.block_read) {
        crate::vlog!("    ✗ BLOCKED by blocked_file_read");
        return v;
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate a file write path (PreToolUse → Write/Edit)
pub fn evaluate_file_write(path: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:write_path {:?}", path);
    if !policy.file_paths.allow_write.is_empty()
        && paths::is_glob_allowed(path, &policy.file_paths.allow_write)
    {
        crate::vlog!("    ✓ allow (allow_write match)");
        return Verdict::Allow;
    }
    crate::vlog!(
        "    detector:blocked_file_write ({} patterns)",
        policy.file_paths.block_write.len()
    );
    if let Some(v) = paths::scan_write(path, &policy.file_paths.block_write) {
        crate::vlog!("    ✗ BLOCKED by blocked_file_write");
        return v;
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate a URL (PreToolUse → WebFetch)
pub fn evaluate_url(url: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:url {:?}", url);
    // URL allowlist: explicit allow (e.g. trusted internal registries) wins over blocklist.
    if !policy.urls.allowlist.is_empty()
        && policy
            .urls
            .allowlist
            .iter()
            .any(|allowed| url.contains(allowed.as_str()))
    {
        crate::vlog!("    ✓ allow (url allowlist match)");
        return Verdict::Allow;
    }
    crate::vlog!(
        "    detector:url_blocklist ({} entries)",
        policy.urls.blocklist.len()
    );
    if let Some(v) = urls::scan(url, &policy.urls.blocklist) {
        crate::vlog!("    ✗ BLOCKED by url_blocklist");
        return v;
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate file content loaded into Claude's context (PostToolUse → Read)
pub fn evaluate_file_content(content: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:file_content ({} chars)", content.len());
    if policy.pii.block_in_file_content {
        crate::vlog!("    detector:pii ({} types)", policy.pii.types.len());
        if let Some(v) = pii::scan(content, &policy.pii.types) {
            crate::vlog!("    ✗ BLOCKED by pii");
            return v;
        }
    }
    crate::vlog!("    detector:secrets");
    if let Some(v) = secrets::scan(content) {
        crate::vlog!("    ✗ BLOCKED by secrets");
        return v;
    }
    if policy.injection.enabled {
        crate::vlog!("    detector:injection");
        if let Some(v) = injection::scan(content) {
            crate::vlog!("    ✗ BLOCKED by injection");
            return v;
        }
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate web content loaded into Claude's context (PostToolUse → WebFetch)
pub fn evaluate_web_content(content: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:web_content ({} chars)", content.len());
    if policy.injection.enabled {
        crate::vlog!("    detector:injection");
        if let Some(v) = injection::scan(content) {
            crate::vlog!("    ✗ BLOCKED by injection");
            return v;
        }
    }
    crate::vlog!("    detector:secrets");
    if let Some(v) = secrets::scan(content) {
        crate::vlog!("    ✗ BLOCKED by secrets");
        return v;
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate bash command output (AfterTool → Bash)
/// Scans stdout/stderr for secrets and PII that the command may have printed
/// (e.g. `cat ~/.env` output if the path check was somehow missed).
pub fn evaluate_bash_output(output: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:bash_output ({} chars)", output.len());
    crate::vlog!("    detector:secrets");
    if let Some(v) = secrets::scan(output) {
        crate::vlog!("    ✗ BLOCKED by secrets");
        return v;
    }
    if policy.pii.block_in_file_content {
        crate::vlog!("    detector:pii ({} types)", policy.pii.types.len());
        if let Some(v) = pii::scan(output, &policy.pii.types) {
            crate::vlog!("    ✗ BLOCKED by pii");
            return v;
        }
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}

/// Evaluate Claude's final response (Stop hook)
pub fn evaluate_response(response: &str, policy: &Policy) -> Verdict {
    crate::vlog!("  check:response ({} chars)", response.len());
    crate::vlog!("    detector:secrets");
    if let Some(v) = secrets::scan(response) {
        crate::vlog!("    ✗ BLOCKED by secrets");
        return v;
    }
    if policy.pii.redact_in_response {
        crate::vlog!("    detector:pii ({} types)", policy.pii.types.len());
        if let Some(v) = pii::scan(response, &policy.pii.types) {
            crate::vlog!("    ✗ BLOCKED by pii");
            return v;
        }
    }
    crate::vlog!("    ✓ allow");
    Verdict::Allow
}
