use crate::detectors::{commands, injection, paths, pii, secrets, urls};
use crate::engine::{policy::Policy, verdict::Verdict};

/// Evaluate a developer's prompt (UserPromptSubmit)
pub fn evaluate_prompt(prompt: &str, policy: &Policy) -> Verdict {
    if policy.injection.enabled {
        if let Some(v) = injection::scan(prompt) {
            return v;
        }
    }
    if policy.pii.block_in_prompt {
        if let Some(v) = pii::scan(prompt, &policy.pii.types) {
            return v;
        }
    }
    Verdict::Allow
}

/// Evaluate a bash command (PreToolUse → Bash)
pub fn evaluate_command(command: &str, policy: &Policy) -> Verdict {
    if policy.bash.enabled {
        if let Some(v) = commands::scan(command, &policy.bash.block_patterns) {
            return v;
        }
    }
    Verdict::Allow
}

/// Evaluate a file read path (PreToolUse → Read)
pub fn evaluate_file_read(path: &str, policy: &Policy) -> Verdict {
    if let Some(v) = paths::scan_read(path, &policy.file_paths.block_read) {
        return v;
    }
    Verdict::Allow
}

/// Evaluate a file write path (PreToolUse → Write/Edit)
pub fn evaluate_file_write(path: &str, policy: &Policy) -> Verdict {
    if let Some(v) = paths::scan_write(path, &policy.file_paths.block_write) {
        return v;
    }
    Verdict::Allow
}

/// Evaluate a URL (PreToolUse → WebFetch)
pub fn evaluate_url(url: &str, policy: &Policy) -> Verdict {
    if let Some(v) = urls::scan(url, &policy.urls.blocklist) {
        return v;
    }
    Verdict::Allow
}

/// Evaluate file content loaded into Claude's context (PostToolUse → Read)
pub fn evaluate_file_content(content: &str, policy: &Policy) -> Verdict {
    if policy.pii.block_in_file_content {
        if let Some(v) = pii::scan(content, &policy.pii.types) {
            return v;
        }
    }
    if let Some(v) = secrets::scan(content) {
        return v;
    }
    if policy.injection.enabled {
        if let Some(v) = injection::scan(content) {
            return v;
        }
    }
    Verdict::Allow
}

/// Evaluate web content loaded into Claude's context (PostToolUse → WebFetch)
pub fn evaluate_web_content(content: &str, policy: &Policy) -> Verdict {
    if policy.injection.enabled {
        if let Some(v) = injection::scan(content) {
            return v;
        }
    }
    if let Some(v) = secrets::scan(content) {
        return v;
    }
    Verdict::Allow
}

/// Evaluate Claude's final response (Stop hook)
pub fn evaluate_response(response: &str, policy: &Policy) -> Verdict {
    if let Some(v) = secrets::scan(response) {
        return v;
    }
    if policy.pii.redact_in_response {
        if let Some(v) = pii::scan(response, &policy.pii.types) {
            return v;
        }
    }
    Verdict::Allow
}
