use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct PreToolPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    pub tool_name: String,
    pub tool_input: Value,
}

/// Handles the PreToolUse hook.
/// Fires before EVERY tool Claude calls — Bash, Write, Read, WebFetch, etc.
/// This is the most critical interception point: stops execution before damage.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PreToolPayload = serde_json::from_str(input)?;
    crate::vlog!("tool={}", payload.tool_name);

    let verdict = match payload.tool_name.as_str() {
        // Claude Code: "Bash" | Copilot: "runInTerminal" | Gemini: "run_bash" | Cursor: "Shell"
        "Bash" | "runInTerminal" | "run_bash" | "Shell" => {
            let command = payload.tool_input["command"].as_str().unwrap_or("");
            crate::vlog!("  command={:?}", command);
            evaluator::evaluate_command(command, policy)
        }
        // Claude Code: "Write" / "Edit" | Copilot: "writeFile" / "editFile" / "editFiles" / "applyPatch" | Gemini: "write_file" / "replace"
        "Write" | "Edit" | "writeFile" | "editFile" | "editFiles" | "applyPatch" | "write_file"
        | "replace" => {
            let path = payload.tool_input["file_path"]
                .as_str()
                .or_else(|| payload.tool_input["path"].as_str())
                .unwrap_or("");
            crate::vlog!("  path={:?}", path);
            evaluator::evaluate_file_write(path, policy)
        }
        // MultiEdit edits multiple files in a single call — check every path.
        "MultiEdit" => {
            let edits = payload.tool_input["edits"].as_array();
            let mut v = Verdict::Allow;
            if let Some(edits) = edits {
                crate::vlog!("  edits={} files", edits.len());
                for edit in edits {
                    let path = edit["file_path"]
                        .as_str()
                        .or_else(|| edit["path"].as_str())
                        .unwrap_or("");
                    crate::vlog!("  path={:?}", path);
                    let result = evaluator::evaluate_file_write(path, policy);
                    if matches!(result, Verdict::Block { .. }) {
                        v = result;
                        break;
                    }
                }
            }
            v
        }
        // Claude Code: "Read" | Copilot: "readFile" | Gemini: "read_file" | Cursor: uses beforeReadFile hook
        "Read" | "readFile" | "read_file" => {
            let path = payload.tool_input["file_path"]
                .as_str()
                .or_else(|| payload.tool_input["path"].as_str())
                .unwrap_or("");
            crate::vlog!("  path={:?}", path);
            evaluator::evaluate_file_read(path, policy)
        }
        // Claude Code: "WebFetch" | Copilot: "fetch" | Gemini: "web_search" / "web_browse" / "http_request"
        "WebFetch" | "fetch" | "web_search" | "web_browse" | "http_request" => {
            let url = payload.tool_input["url"].as_str().unwrap_or("");
            crate::vlog!("  url={:?}", url);
            evaluator::evaluate_url(url, policy)
        }
        // Cursor: Delete — treat as a path write check to block access to protected paths
        "Delete" => {
            let path = payload.tool_input["file_path"]
                .as_str()
                .or_else(|| payload.tool_input["path"].as_str())
                .unwrap_or("");
            crate::vlog!("  delete path={:?}", path);
            evaluator::evaluate_file_write(path, policy)
        }
        // Cursor: Grep — read-only search, no security action needed
        "Grep" => Verdict::Allow,
        "Task" => {
            // Sub-agent spawn — log but allow (sub-agent hooks fire separately)
            crate::vlog!("  sub-agent spawn — skipped (sub-agent hooks fire separately)");
            Verdict::Allow
        }
        _ => {
            // Unrecognised tool — allow but warn loudly so version skew doesn't
            // create a silent security gap. Update kiteguard if a new tool appears.
            eprintln!(
                "kiteguard: WARNING — unrecognised tool '{}'; security checks skipped. \
If this is a new tool from your AI runtime, update kiteguard to add explicit handling.",
                payload.tool_name
            );
            crate::vlog!("  unknown tool — allow");
            Verdict::Allow
        }
    };

    Ok(verdict)
}

// ---------------------------------------------------------------------------
// Cursor-specific handlers — different payload schemas from preToolUse
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ShellExecPayload {
    pub command: String,
    #[allow(dead_code)]
    pub cwd: Option<String>,
}

/// Handles Cursor's `beforeShellExecution` hook.
/// The command string sits at the top level, not nested under `tool_input`.
pub fn handle_shell_exec(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: ShellExecPayload = serde_json::from_str(input)?;
    crate::vlog!("  shell command={:?}", payload.command);
    Ok(evaluator::evaluate_command(&payload.command, policy))
}

#[derive(Debug, Deserialize)]
pub struct ReadFilePayload {
    pub file_path: String,
    /// Cursor provides full file content before the model sees it — scan both
    /// path and content in one hook invocation.
    #[serde(default)]
    pub content: String,
}

/// Handles Cursor's `beforeReadFile` hook.
/// Checks the path first, then scans the full file content for secrets/PII
/// before it is sent to the model.
pub fn handle_read_file(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: ReadFilePayload = serde_json::from_str(input)?;
    crate::vlog!("  read file_path={:?}", payload.file_path);
    let path_verdict = evaluator::evaluate_file_read(&payload.file_path, policy);
    if matches!(path_verdict, Verdict::Block { .. }) {
        return Ok(path_verdict);
    }
    if !payload.content.is_empty() {
        crate::vlog!("  content ({} chars)", payload.content.len());
        return Ok(evaluator::evaluate_file_content(&payload.content, policy));
    }
    Ok(Verdict::Allow)
}

#[derive(Debug, Deserialize)]
pub struct McpExecPayload {
    /// MCP tool name (e.g. "search", "database_query")
    #[serde(default)]
    pub tool_name: String,
    /// MCP tool parameters as a JSON string — scan for secrets/injection.
    #[serde(default)]
    pub tool_input: String,
    /// MCP server URL (stdio-based servers omit this; HTTP-based servers include it).
    pub url: Option<String>,
    /// MCP server command (stdio servers include this instead of url).
    pub command: Option<String>,
}

/// Handles Cursor's `beforeMCPExecution` hook.
/// MCP tools can call external APIs, databases, or run code — check the server
/// URL for SSRF, the command for dangerous patterns, and scan the tool_input
/// for secrets or injection being passed to third-party MCP servers.
pub fn handle_mcp_exec(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: McpExecPayload = serde_json::from_str(input)?;
    crate::vlog!("  mcp tool={:?}", payload.tool_name);

    // 1. Check server URL for SSRF / blocklist (HTTP-based MCP servers)
    if let Some(ref url) = payload.url {
        crate::vlog!("  mcp url={:?}", url);
        let v = evaluator::evaluate_url(url, policy);
        if matches!(v, Verdict::Block { .. }) {
            return Ok(v);
        }
    }

    // 2. Check server command for dangerous patterns (stdio-based MCP servers)
    if let Some(ref cmd) = payload.command {
        crate::vlog!("  mcp command={:?}", cmd);
        let v = evaluator::evaluate_command(cmd, policy);
        if matches!(v, Verdict::Block { .. }) {
            return Ok(v);
        }
    }

    // 3. Scan tool_input (the params sent to the MCP tool) for secrets/injection
    //    that the agent might be exfiltrating to an external service.
    if !payload.tool_input.is_empty() {
        crate::vlog!("  mcp tool_input ({} chars)", payload.tool_input.len());
        let v = evaluator::evaluate_file_content(&payload.tool_input, policy);
        if matches!(v, Verdict::Block { .. }) {
            return Ok(v);
        }
    }

    Ok(Verdict::Allow)
}

/// Handles Cursor's `beforeTabFileRead` hook.
/// Tab (inline completions) reads files before generating code suggestions.
/// Reuses `handle_read_file` — same payload schema, same security checks.
pub fn handle_tab_read(input: &str, policy: &Policy) -> Result<Verdict> {
    handle_read_file(input, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::{
        BashPolicy, FilePathPolicy, InjectionPolicy, PiiPolicy, Policy, UrlPolicy,
    };

    fn policy() -> Policy {
        Policy {
            bash: BashPolicy {
                enabled: true,
                block_patterns: vec![r"rm\s+-rf".to_string()],
                allow_patterns: vec![],
                block_on_error: true,
            },
            file_paths: FilePathPolicy {
                block_read: vec!["**/.ssh/**".to_string(), "**/.env".to_string()],
                block_write: vec!["/etc/**".to_string()],
                allow_read: vec![],
                allow_write: vec![],
            },
            pii: PiiPolicy {
                block_in_prompt: true,
                block_in_file_content: true,
                redact_in_response: false,
                types: vec!["ssn".into(), "email".into(), "credit_card".into()],
            },
            urls: UrlPolicy {
                blocklist: vec!["evil.com".to_string()],
                allowlist: vec![],
            },
            injection: InjectionPolicy { enabled: true },
            webhook: None,
            version: None,
            remote_policy_url: None,
        }
    }

    // ── handle_shell_exec ────────────────────────────────────────────────────

    #[test]
    fn shell_exec_dangerous_command_blocked() {
        let input = r#"{"command": "rm -rf /home/user", "cwd": "/tmp"}"#;
        let v = handle_shell_exec(input, &policy()).unwrap();
        assert!(v.is_block(), "rm -rf should be blocked");
    }

    #[test]
    fn shell_exec_safe_command_allowed() {
        let input = r#"{"command": "git status", "cwd": "/tmp"}"#;
        let v = handle_shell_exec(input, &policy()).unwrap();
        assert!(v.is_allow(), "git status should be allowed");
    }

    #[test]
    fn shell_exec_empty_command_allowed() {
        let input = r#"{"command": "", "cwd": "/tmp"}"#;
        let v = handle_shell_exec(input, &policy()).unwrap();
        assert!(v.is_allow(), "empty command should be allowed");
    }

    // ── handle_read_file ─────────────────────────────────────────────────────

    #[test]
    fn read_file_sensitive_path_blocked() {
        let input = r#"{"file_path": "/home/user/.ssh/id_rsa", "content": ""}"#;
        let v = handle_read_file(input, &policy()).unwrap();
        assert!(v.is_block(), ".ssh path should be blocked");
    }

    #[test]
    fn read_file_safe_path_allowed() {
        let input = r#"{"file_path": "/home/user/project/main.rs", "content": ""}"#;
        let v = handle_read_file(input, &policy()).unwrap();
        assert!(v.is_allow(), "safe path should be allowed");
    }

    #[test]
    fn read_file_content_with_secret_blocked() {
        let input = r#"{"file_path": "/home/user/config.txt", "content": "AKIAIOSFODNN7EXAMPLE"}"#;
        let v = handle_read_file(input, &policy()).unwrap();
        assert!(v.is_block(), "AWS key in file content should be blocked");
    }

    #[test]
    fn read_file_safe_content_allowed() {
        let input = r#"{"file_path": "/home/user/notes.txt", "content": "Hello world"}"#;
        let v = handle_read_file(input, &policy()).unwrap();
        assert!(v.is_allow(), "clean content should be allowed");
    }

    #[test]
    fn read_file_no_content_field_allowed() {
        let input = r#"{"file_path": "/home/user/readme.md"}"#;
        let v = handle_read_file(input, &policy()).unwrap();
        assert!(
            v.is_allow(),
            "missing content defaults to empty and should allow"
        );
    }

    // ── handle_tab_read ──────────────────────────────────────────────────────

    #[test]
    fn tab_read_sensitive_path_blocked() {
        let input = r#"{"file_path": "/home/user/.env", "content": ""}"#;
        let v = handle_tab_read(input, &policy()).unwrap();
        assert!(v.is_block(), ".env path should be blocked in tab read");
    }

    #[test]
    fn tab_read_safe_path_allowed() {
        let input = r#"{"file_path": "/home/user/src/lib.rs", "content": "fn main() {}"}"#;
        let v = handle_tab_read(input, &policy()).unwrap();
        assert!(v.is_allow(), "safe tab read should be allowed");
    }

    // ── handle_mcp_exec ──────────────────────────────────────────────────────

    #[test]
    fn mcp_exec_ssrf_url_blocked() {
        let input = r#"{"tool_name": "fetch", "url": "http://169.254.169.254/latest/meta-data/", "tool_input": ""}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(v.is_block(), "SSRF metadata URL should be blocked");
    }

    #[test]
    fn mcp_exec_blocked_domain_url_blocked() {
        let input = r#"{"tool_name": "fetch", "url": "https://evil.com/data", "tool_input": ""}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(v.is_block(), "blocked domain in MCP url should be blocked");
    }

    #[test]
    fn mcp_exec_dangerous_command_blocked() {
        let input = r#"{"tool_name": "shell", "command": "rm -rf /", "tool_input": ""}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(
            v.is_block(),
            "dangerous MCP server command should be blocked"
        );
    }

    #[test]
    fn mcp_exec_secret_in_tool_input_blocked() {
        let input =
            r#"{"tool_name": "query", "tool_input": "{\"api_key\": \"AKIAIOSFODNN7EXAMPLE\"}"}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(v.is_block(), "AWS key in MCP tool_input should be blocked");
    }

    #[test]
    fn mcp_exec_safe_call_allowed() {
        let input = r#"{"tool_name": "search", "url": "https://api.example.com/search", "tool_input": "{\"query\": \"rust programming\"}"}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(v.is_allow(), "safe MCP call should be allowed");
    }

    #[test]
    fn mcp_exec_no_url_no_command_allowed() {
        let input = r#"{"tool_name": "list_files", "tool_input": "{\"path\": \"/tmp\"}"}"#;
        let v = handle_mcp_exec(input, &policy()).unwrap();
        assert!(
            v.is_allow(),
            "MCP call with no url/command should be allowed"
        );
    }
}
