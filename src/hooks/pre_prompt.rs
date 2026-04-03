use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PrePromptPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    /// Present in:
    ///   UserPromptSubmit  (Claude Code)
    ///   BeforeAgent       (Gemini CLI)
    ///   beforeSubmitPrompt (Cursor) — also has `attachments` array, ignored here
    pub prompt: Option<String>,
}

/// Handles prompt scan hooks across runtimes:
///   UserPromptSubmit   (Claude Code)
///   BeforeAgent        (Gemini CLI)
///   beforeSubmitPrompt (Cursor)
/// Inspects the developer's prompt for PII and prompt injection before
/// it reaches the model.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PrePromptPayload = serde_json::from_str(input)?;
    let prompt = payload.prompt.as_deref().unwrap_or("");
    crate::vlog!("prompt ({} chars): {:?}", prompt.len(), prompt);
    Ok(evaluator::evaluate_prompt(prompt, policy))
}
