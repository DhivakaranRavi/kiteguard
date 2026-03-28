use crate::engine::{policy::WebhookConfig, verdict::Verdict};
use anyhow::Result;

/// Sends an audit event to the configured webhook endpoint.
/// Non-blocking best-effort — failures are silently dropped to avoid
/// impacting Claude Code's operation.
pub fn send(config: &WebhookConfig, hook_event: &str, verdict: &Verdict) -> Result<()> {
    if config.url.is_empty() {
        return Ok(());
    }

    let body = serde_json::json!({
        "source":  "kiteguard",
        "hook":    hook_event,
        "verdict": verdict.as_str(),
    });

    let mut req = ureq::post(&config.url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "kiteguard/0.1.0");

    if let Some(ref token) = config.token {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }

    req.send_string(&body.to_string())?;
    Ok(())
}
