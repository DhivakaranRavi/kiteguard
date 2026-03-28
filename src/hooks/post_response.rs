use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use crate::engine::{policy::Policy, verdict::Verdict, evaluator};

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

    // Get the last assistant message from transcript
    let last_response = payload
        .transcript
        .iter()
        .rev()
        .find(|msg| msg["role"].as_str() == Some("assistant"))
        .and_then(|msg| msg["content"].as_str())
        .unwrap_or("");

    if last_response.is_empty() {
        return Ok(Verdict::Allow);
    }

    Ok(evaluator::evaluate_response(last_response, policy))
}
