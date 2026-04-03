use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct PostToolPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    /// Tool name: present in PostToolUse (Claude/Copilot) and AfterTool (Gemini).
    #[serde(default)]
    pub tool_name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub tool_input: Value,
    /// Tool response: present in PostToolUse (Claude/Copilot) and AfterTool (Gemini).
    #[serde(default)]
    pub tool_response: Value,
}

/// Handles the PostToolUse hook.
/// Fires after a tool executes — scans the actual content returned
/// (file contents, web page responses) for PII, secrets, and injection.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PostToolPayload = serde_json::from_str(input)?;
    crate::vlog!("tool={} (post)", payload.tool_name);

    // Extract text content from the tool response
    let content = extract_content(&payload.tool_response);
    if content.is_empty() {
        crate::vlog!("  response_content empty — skip");
        return Ok(Verdict::Allow);
    }
    crate::vlog!("  response_content ({} chars)", content.len());

    // Scan content that just loaded into Claude's context
    let verdict = match payload.tool_name.as_str() {
        // File content — scan for PII, secrets, injection
        "Read" | "readFile" | "read_file" => evaluator::evaluate_file_content(&content, policy),
        // Web content — scan for injection, secrets
        "WebFetch" | "fetch" | "web_search" | "web_browse" | "http_request" => {
            evaluator::evaluate_web_content(&content, policy)
        }
        // Bash output — scan for secrets/PII that the command may have printed
        // (e.g. `cat ~/.ssh/id_rsa` output if BeforeTool was somehow bypassed)
        // Cursor: "Shell" maps to the bash output check.
        "Bash" | "runInTerminal" | "run_bash" | "Shell" => {
            evaluator::evaluate_bash_output(&content, policy)
        }
        _ => Verdict::Allow,
    };

    Ok(verdict)
}

fn extract_content(response: &Value) -> String {
    // Claude Code returns tool responses in various shapes.
    // Plain string
    if let Some(s) = response.as_str() {
        return s.to_string();
    }
    // "content" key — may be a plain string OR a block array
    // ([{"type":"text","text":"..."}]). Checking only .as_str() returns
    // None for the array form, silently skipping all scans (scan bypass).
    let content_val = &response["content"];
    if let Some(s) = content_val.as_str() {
        return s.to_string();
    }
    if let Some(blocks) = content_val.as_array() {
        let text = blocks
            .iter()
            .filter_map(|block| {
                if block["type"].as_str() == Some("text") {
                    block["text"].as_str()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            return text;
        }
    }
    // Fallback: plain "output" key (some tool wrappers use this shape)
    if let Some(s) = response["output"].as_str() {
        return s.to_string();
    }
    // Unknown format — log loudly so new runtime response shapes don't
    // silently bypass post-tool PII/secrets scanning.
    eprintln!(
        "kiteguard: WARNING — unrecognised tool response format; \
post-tool PII/secrets scan could not be applied. \
Report this at https://github.com/rustic-ai/kiteguard/issues."
    );
    String::new()
}

// ---------------------------------------------------------------------------
// Cursor-specific handler
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ShellOutputPayload {
    #[allow(dead_code)]
    #[serde(default)]
    pub command: String,
    /// Full terminal output from the shell command.
    #[serde(default)]
    pub output: String,
}

/// Handles Cursor's `afterShellExecution` hook.
/// The terminal output is at the top level (not nested in `tool_response`).
pub fn handle_shell_output(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: ShellOutputPayload = serde_json::from_str(input)?;
    if payload.output.is_empty() {
        crate::vlog!("  afterShellExecution output empty — skip");
        return Ok(Verdict::Allow);
    }
    crate::vlog!(
        "  afterShellExecution output ({} chars)",
        payload.output.len()
    );
    Ok(evaluator::evaluate_bash_output(&payload.output, policy))
}

#[derive(Debug, Deserialize)]
pub struct McpOutputPayload {
    #[allow(dead_code)]
    #[serde(default)]
    pub tool_name: String,
    /// Full JSON result returned by the MCP tool — scan for secrets/PII
    /// that the external service may have returned into the model's context.
    #[serde(default)]
    pub result_json: String,
}

/// Handles Cursor's `afterMCPExecution` hook.
/// Scans the MCP tool result for secrets/PII before it reaches the model.
pub fn handle_mcp_output(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: McpOutputPayload = serde_json::from_str(input)?;
    if payload.result_json.is_empty() {
        crate::vlog!("  afterMCPExecution result_json empty — skip");
        return Ok(Verdict::Allow);
    }
    crate::vlog!(
        "  afterMCPExecution result_json ({} chars)",
        payload.result_json.len()
    );
    Ok(evaluator::evaluate_file_content(
        &payload.result_json,
        policy,
    ))
}

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use crate::engine::policy::{
        BashPolicy, FilePathPolicy, InjectionPolicy, PiiPolicy, Policy, UrlPolicy,
    };

    fn policy() -> Policy {
        Policy {
            bash: BashPolicy {
                enabled: true,
                block_patterns: vec![],
                block_on_error: true,
            },
            file_paths: FilePathPolicy {
                block_read: vec![],
                block_write: vec![],
            },
            pii: PiiPolicy {
                block_in_prompt: false,
                block_in_file_content: true,
                redact_in_response: true,
                types: vec!["ssn".into(), "email".into(), "credit_card".into()],
            },
            urls: UrlPolicy { blocklist: vec![] },
            injection: InjectionPolicy { enabled: true },
            webhook: None,
        }
    }

    // ── handle_shell_output ──────────────────────────────────────────────────

    #[test]
    fn shell_output_with_private_key_blocked() {
        let input = r#"{"output": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"}"#;
        let v = handle_shell_output(input, &policy()).unwrap();
        assert!(
            v.is_block(),
            "private key in shell output should be blocked"
        );
    }

    #[test]
    fn shell_output_clean_allowed() {
        let input = r#"{"output": "total 42\ndrwxr-xr-x  5 user group 160 Apr 2 12:00 ."}"#;
        let v = handle_shell_output(input, &policy()).unwrap();
        assert!(v.is_allow(), "clean shell output should be allowed");
    }

    #[test]
    fn shell_output_empty_allowed() {
        let input = r#"{"output": ""}"#;
        let v = handle_shell_output(input, &policy()).unwrap();
        assert!(v.is_allow(), "empty shell output should be allowed");
    }

    #[test]
    fn shell_output_missing_field_allowed() {
        let input = r#"{}"#;
        let v = handle_shell_output(input, &policy()).unwrap();
        assert!(
            v.is_allow(),
            "missing output field defaults to empty and should allow"
        );
    }

    // ── handle_mcp_output ────────────────────────────────────────────────────

    #[test]
    fn mcp_output_with_aws_key_blocked() {
        let input =
            r#"{"tool_name": "fetch", "result_json": "{\"token\": \"AKIAIOSFODNN7EXAMPLE\"}"}"#;
        let v = handle_mcp_output(input, &policy()).unwrap();
        assert!(v.is_block(), "AWS key in MCP result should be blocked");
    }

    #[test]
    fn mcp_output_clean_allowed() {
        let input = r#"{"tool_name": "search", "result_json": "{\"results\": [\"item1\"]}"}"#;
        let v = handle_mcp_output(input, &policy()).unwrap();
        assert!(v.is_allow(), "clean MCP result should be allowed");
    }

    #[test]
    fn mcp_output_empty_result_allowed() {
        let input = r#"{"tool_name": "noop", "result_json": ""}"#;
        let v = handle_mcp_output(input, &policy()).unwrap();
        assert!(v.is_allow(), "empty MCP result should be allowed");
    }
}
