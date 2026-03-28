use crate::engine::{policy::WebhookConfig, verdict::Verdict};
use crate::error::Result;

/// Sends an audit event to the configured webhook endpoint via curl.
/// Non-blocking best-effort — failures are silently dropped to avoid
/// impacting Claude Code's operation.
pub fn send(config: &WebhookConfig, hook_event: &str, verdict: &Verdict) -> Result<()> {
    if config.url.is_empty() {
        return Ok(());
    }

    let body = format!(
        r#"{{"source":"kiteguard","hook":"{}","verdict":"{}"}}"#,
        hook_event,
        verdict.as_str()
    );

    let mut cmd = std::process::Command::new("curl");
    cmd.arg("-s")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg("User-Agent: kiteguard/0.1.0")
        .arg("-d")
        .arg(&body);

    if let Some(ref token) = config.token {
        cmd.arg("-H")
            .arg(format!("Authorization: Bearer {}", token));
    }

    cmd.arg(&config.url);
    let _ = cmd.output(); // best-effort, ignore errors
    Ok(())
}
