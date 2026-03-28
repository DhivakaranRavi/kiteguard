use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct StopPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    pub transcript: Vec<Value>,
}

/// Handles the Stop hook.
/// Fires after Claude generates its final response.
/// Scans for secrets, API keys, and PII before the developer sees the output.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: StopPayload = serde_json::from_str(input)?;

    // Get the last assistant message from transcript.
    // Claude's API may return `content` as a plain string OR as an array of
    // content blocks ([{"type":"text","text":"..."}]).  Checking only `.as_str()`
    // would silently skip scanning on array-shaped responses — a scan bypass.
    let last_response = payload
        .transcript
        .iter()
        .rev()
        .find(|msg| msg["role"].as_str() == Some("assistant"))
        .map(|msg| extract_text_content(&msg["content"]))
        .unwrap_or_default();

    if last_response.is_empty() {
        return Ok(Verdict::Allow);
    }

    Ok(evaluator::evaluate_response(&last_response, policy))
}

/// Extracts plain text from a Claude content value, handling both:
/// - String: `"hello world"`
/// - Block array: `[{"type":"text","text":"hello world"}, ...]`
fn extract_text_content(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(blocks) = content.as_array() {
        return blocks
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
    }
    String::new()
}
