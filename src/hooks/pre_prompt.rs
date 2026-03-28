use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PrePromptPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    pub prompt: String,
}

/// Handles the UserPromptSubmit hook.
/// Inspects the developer's prompt for PII and prompt injection before
/// it reaches the Claude API.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PrePromptPayload = serde_json::from_str(input)?;
    Ok(evaluator::evaluate_prompt(&payload.prompt, policy))
}
