use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use crate::engine::{policy::Policy, verdict::Verdict, evaluator};

#[derive(Debug, Deserialize)]
pub struct PreToolPayload {
    pub session_id: Option<String>,
    pub tool_name: String,
    pub tool_input: Value,
}

/// Handles the PreToolUse hook.
/// Fires before EVERY tool Claude calls — Bash, Write, Read, WebFetch, etc.
/// This is the most critical interception point: stops execution before damage.
pub fn handle(input: &str, policy: &Policy) -> Result<Verdict> {
    let payload: PreToolPayload = serde_json::from_str(input)?;

    let verdict = match payload.tool_name.as_str() {
        "Bash" => {
            let command = payload.tool_input["command"]
                .as_str()
                .unwrap_or("");
            evaluator::evaluate_command(command, policy)
        }
        "Write" | "Edit" => {
            let path = payload.tool_input["file_path"]
                .as_str()
                .or_else(|| payload.tool_input["path"].as_str())
                .unwrap_or("");
            evaluator::evaluate_file_write(path, policy)
        }
        "Read" => {
            let path = payload.tool_input["file_path"]
                .as_str()
                .or_else(|| payload.tool_input["path"].as_str())
                .unwrap_or("");
            evaluator::evaluate_file_read(path, policy)
        }
        "WebFetch" => {
            let url = payload.tool_input["url"]
                .as_str()
                .unwrap_or("");
            evaluator::evaluate_url(url, policy)
        }
        "Task" => {
            // Sub-agent spawn — log but allow (sub-agent hooks fire separately)
            Verdict::Allow
        }
        _ => Verdict::Allow,
    };

    Ok(verdict)
}
