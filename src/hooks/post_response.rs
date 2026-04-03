use crate::engine::{evaluator, policy::Policy, verdict::Verdict};
use crate::error::Result;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct StopPayload {
    #[allow(dead_code)]
    pub session_id: Option<String>,
    /// Present in Claude Code Stop hook; absent in Gemini AfterAgent.
    #[serde(default)]
    pub transcript: Vec<Value>,
}

/// Handles the Stop hook (Claude Code) and AfterAgent hook (Gemini).
/// Fires after the model generates its final response.
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
        crate::vlog!("  transcript last_response empty — skip");
        return Ok(Verdict::Allow);
    }
    crate::vlog!("  transcript last_response ({} chars)", last_response.len());

    Ok(evaluator::evaluate_response(&last_response, policy))
}

// ---------------------------------------------------------------------------
// Cursor-specific handler
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AgentResponsePayload {
    /// Plain response text — Cursor's afterAgentResponse delivers it here.
    #[serde(default)]
    pub text: String,
}

/// Handles Cursor's `afterAgentResponse` hook.
/// Fires after the agent completes an assistant message; scans for secrets/PII
/// before the developer sees the output.
pub fn handle_agent_response(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: AgentResponsePayload = serde_json::from_str(input)?;
    if payload.text.is_empty() {
        crate::vlog!("  afterAgentResponse text empty — skip");
        return Ok(Verdict::Allow);
    }
    crate::vlog!("  afterAgentResponse ({} chars)", payload.text.len());
    Ok(evaluator::evaluate_response(&payload.text, policy))
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

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use crate::engine::policy::{
        BashPolicy, FilePathPolicy, InjectionPolicy, PiiPolicy, Policy, UrlPolicy,
    };

    fn policy() -> Policy {
        Policy {
            bash: BashPolicy {
                enabled: false,
                block_patterns: vec![],
                block_on_error: false,
            },
            file_paths: FilePathPolicy {
                block_read: vec![],
                block_write: vec![],
            },
            pii: PiiPolicy {
                block_in_prompt: false,
                block_in_file_content: false,
                redact_in_response: true,
                types: vec!["ssn".into(), "email".into(), "credit_card".into()],
            },
            urls: UrlPolicy { blocklist: vec![] },
            injection: InjectionPolicy { enabled: false },
            webhook: None,
        }
    }

    // ── handle_agent_response ────────────────────────────────────────────────

    #[test]
    fn agent_response_with_secret_blocked() {
        let input = r#"{"text": "Here is your key: AKIAIOSFODNN7EXAMPLE"}"#;
        let v = handle_agent_response(input, &policy()).unwrap();
        assert!(v.is_block(), "secret in agent response should be blocked");
    }

    #[test]
    fn agent_response_clean_allowed() {
        let input = r#"{"text": "Sure, here is a summary of your code changes."}"#;
        let v = handle_agent_response(input, &policy()).unwrap();
        assert!(v.is_allow(), "clean agent response should be allowed");
    }

    #[test]
    fn agent_response_empty_text_allowed() {
        let input = r#"{"text": ""}"#;
        let v = handle_agent_response(input, &policy()).unwrap();
        assert!(v.is_allow(), "empty response text should be allowed");
    }
}
