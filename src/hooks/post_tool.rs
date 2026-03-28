use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct PostToolPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    pub tool_name: String,
    #[allow(dead_code)]
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
    String::new()
}
