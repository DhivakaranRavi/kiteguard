use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use crate::engine::{policy::Policy, verdict::Verdict, evaluator};

#[derive(Debug, Deserialize)]
pub struct PostToolPayload {
    pub session_id: Option<String>,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_response: Value,
}

/// Handles the PostToolUse hook.
/// Fires after a tool executes — scans the actual content returned
/// (file contents, web page responses) for PII, secrets, and injection.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PostToolPayload = serde_json::from_str(input)?;

    // Extract text content from the tool response
    let content = extract_content(&payload.tool_response);
    if content.is_empty() {
        return Ok(Verdict::Allow);
    }

    // Scan content that just loaded into Claude's context
    let verdict = match payload.tool_name.as_str() {
        "Read" => evaluator::evaluate_file_content(&content, policy),
        "WebFetch" => evaluator::evaluate_web_content(&content, policy),
        _ => Verdict::Allow,
    };

    Ok(verdict)
}

fn extract_content(response: &Value) -> String {
    // Claude Code returns tool responses in various shapes
    if let Some(s) = response.as_str() {
        return s.to_string();
    }
    if let Some(s) = response["content"].as_str() {
        return s.to_string();
    }
    if let Some(s) = response["output"].as_str() {
        return s.to_string();
    }
    String::new()
}
