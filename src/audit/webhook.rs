use crate::engine::{policy::WebhookConfig, verdict::Verdict};
use crate::error::Result;

/// Canonical SSRF-protected endpoints shared with urls.rs.
pub const SSRF_BLOCKED: &[&str] = &[
    "169.254.169.254", // AWS/GCP/Azure IMDS
    "metadata.google.internal",
    "metadata.azure.com",
    "fd00:ec2::254", // IPv6 AWS metadata
    "localhost",
    "127.0.0.1",
    "[::1]",
];

/// Returns false if the URL targets a private/metadata endpoint.
fn is_ssrf_safe(url: &str) -> bool {
    let lower = url.to_lowercase();
    for blocked in SSRF_BLOCKED {
        if lower.contains(blocked) {
            return false;
        }
    }
    // Block private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
    let private_re =
        regex::Regex::new(r"(?:^|[/@:])(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)");
    if let Ok(r) = private_re {
        if r.is_match(&lower) {
            return false;
        }
    }
    true
}

/// Sends an audit event to the configured webhook endpoint via curl.
/// The Authorization token is passed through curl's stdin config (-K -)
/// so it never appears in `ps aux` or the process table.
/// Non-blocking best-effort — failures are silently dropped to avoid
/// impacting Claude Code's operation.
pub fn send(config: &WebhookConfig, hook_event: &str, verdict: &Verdict) -> Result<()> {
    if config.url.is_empty() {
        return Ok(());
    }

    // SSRF guard — never POST to private/metadata endpoints.
    if !is_ssrf_safe(&config.url) {
        eprintln!(
            "kiteguard: webhook URL blocked (SSRF protection): {}",
            config.url
        );
        return Ok(());
    }

    let body = format!(
        r#"{{"source":"kiteguard","hook":"{}","verdict":"{}"}}"#,
        hook_event,
        verdict.as_str()
    );

    // Build a curl config block piped via stdin — token never hits the
    // process list. If token starts with '$', resolve from env var.
    let resolved_token = config.token.as_ref().map(|t| {
        if let Some(var_name) = t.strip_prefix('$') {
            std::env::var(var_name).unwrap_or_default()
        } else {
            t.clone()
        }
    });

    let mut curl_cfg = format!(
        "url = \"{url}\"\nrequest = POST\nheader = \"Content-Type: application/json\"\nheader = \"User-Agent: kiteguard/0.1.0\"\ndata = {body}",
        url = config.url,
        body = body
    );
    if let Some(ref tok) = resolved_token {
        if !tok.is_empty() {
            curl_cfg.push_str(&format!("\nheader = \"Authorization: Bearer {}\"", tok));
        }
    }

    use std::io::Write;
    let mut child = match std::process::Command::new("curl")
        .arg("-s")
        .arg("-K")
        .arg("-") // read config from stdin
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(()), // curl not available — best-effort
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(curl_cfg.as_bytes());
    }
    let _ = child.wait();
    Ok(())
}
