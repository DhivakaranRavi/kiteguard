use crate::engine::{policy::WebhookConfig, verdict::Verdict};
use crate::error::Result;

/// Canonical SSRF-protected hostnames shared with urls.rs.
/// Covers cloud metadata services by name; private IP ranges are caught by
/// the IP-level check in `is_ssrf_safe` which handles hex/octal/decimal-int
/// encodings that would bypass a simple string match.
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
///
/// Two layers of protection:
/// 1. String-match against known metadata hostnames (catches by name).
/// 2. IP parsing that handles all alternate encodings:
///    - Standard dotted: 127.0.0.1
///    - Hex integer:     0x7f000001
///    - Decimal integer: 2130706433
///    - Octal-dotted:    0177.0.0.1
///    - IPv4-mapped IPv6: ::ffff:127.0.0.1
///
/// Both the raw URL and a percent-decoded copy are checked so that encodings
/// like `http://127%2e0%2e0%2e1/` cannot bypass the host extraction + IP check.
pub fn is_ssrf_safe(url: &str) -> bool {
    let lower = url.to_lowercase();
    let decoded = percent_decode_host(&lower);

    // Layer 1: known hostname string-match (raw and decoded)
    for blocked in SSRF_BLOCKED {
        if lower.contains(blocked) || decoded.contains(blocked) {
            return false;
        }
    }

    // Layer 2: IP-level CIDR check (handles encoded/alternate notations)
    // Run against both the raw URL string and the percent-decoded copy.
    for candidate in [lower.as_str(), decoded.as_str()] {
        if let Some(host) = extract_host(candidate) {
            if let Some(ip) = parse_ip_any(&host) {
                if is_blocked_ip(ip) {
                    return false;
                }
            }
        }
    }

    true
}

/// Decode `%XX` sequences in a URL string so that percent-encoded private IPs
/// (e.g. `127%2e0%2e0%2e1`) are caught by the hostname and IP checks.
/// Only ASCII characters are relevant for hostnames; non-ASCII percent sequences
/// are left as the decoded byte cast to char (safe for comparison purposes).
fn percent_decode_host(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Extracts the hostname from a URL, stripping scheme, userinfo, port, and path.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.find("://").map(|i| &url[i + 3..])?;
    // Strip userinfo (user:pass@host)
    let host_part = match after_scheme.rfind('@') {
        Some(at) => &after_scheme[at + 1..],
        None => after_scheme,
    };
    // Find end of authority
    let end = host_part.find(['/', '?', '#']).unwrap_or(host_part.len());
    let host_port = &host_part[..end];

    // IPv6 literal: [::1] or [::1]:443
    if host_port.starts_with('[') {
        let close = host_port.find(']')?;
        Some(host_port[1..close].to_string())
    } else {
        // Strip port
        let host = match host_port.rfind(':') {
            Some(colon) => &host_port[..colon],
            None => host_port,
        };
        Some(host.to_string())
    }
}

/// Parses a host string as an IP address, handling alternate encodings that
/// bypass naive string-matching SSRF checks.
fn parse_ip_any(host: &str) -> Option<std::net::IpAddr> {
    use std::net::IpAddr;

    // Standard: 127.0.0.1, ::1, ::ffff:127.0.0.1
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }

    // Hex IPv4: 0x7f000001
    if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(n.to_be_bytes())));
        }
    }

    // Decimal-integer IPv4: 2130706433
    if host.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = host.parse::<u32>() {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(n.to_be_bytes())));
        }
    }

    // Octal-dotted IPv4: 0177.0.0.1
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 {
        let mut octets = [0u8; 4];
        let mut valid = true;
        for (i, part) in parts.iter().enumerate() {
            let val = if part.starts_with('0') && part.len() > 1 {
                u8::from_str_radix(&part[1..], 8).ok()
            } else {
                part.parse::<u8>().ok()
            };
            match val {
                Some(v) => octets[i] = v,
                None => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
        }
    }

    None
}

/// Returns true if the IP belongs to any blocked range.
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 127                                        // 127.0.0.0/8 loopback
                || o[0] == 10                                  // 10.0.0.0/8 private
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16–31.x private
                || (o[0] == 192 && o[1] == 168)                // 192.168.x.x private
                || (o[0] == 169 && o[1] == 254)                // 169.254.x.x link-local
                || o[0] == 0                                   // 0.0.0.0/8 source address
                || (o[0] == 100 && (64..=127).contains(&o[1]))  // 100.64.0.0/10 CGNAT (RFC 6598)
                || (o[0] == 198 && (18..=19).contains(&o[1]))  // 198.18.0.0/15 benchmarking (RFC 2544)
                || o[0] >= 224                                 // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                                        // ::1
                || (v6.segments()[0] & 0xfe00) == 0xfc00            // fc00::/7 ULA (covers fd00::)
                || (v6.segments()[0] & 0xffc0) == 0xfe80            // fe80::/10 link-local
                || v6.is_multicast()                                // ff00::/8 multicast
                || match v6.to_ipv4_mapped() {                      // ::ffff:0:0/96
                    Some(v4) => {
                        let o = v4.octets();
                        o[0] == 127
                            || o[0] == 10
                            || (o[0] == 172 && (16..=31).contains(&o[1]))
                            || (o[0] == 192 && o[1] == 168)
                            || (o[0] == 169 && o[1] == 254)
                            || (o[0] == 100 && (64..=127).contains(&o[1]))
                            || o[0] >= 224
                    }
                    None => false,
                }
        }
    }
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

    // Use serde_json to build the body — avoids JSON injection if hook_event
    // or verdict contain control characters or double-quotes.
    // Include full attribution context so receivers can correlate with the audit log.
    let body = serde_json::json!({
        "source":  "kiteguard",
        "ts":      crate::util::timestamp(),
        "hook":    hook_event,
        "verdict": verdict.as_str(),
        "rule":    match verdict { crate::engine::verdict::Verdict::Block { rule, .. } => rule.as_str(), _ => "" },
        "user":    crate::audit::logger::identity_user(),
        "host":    crate::audit::logger::identity_host(),
        "repo":    crate::audit::logger::identity_repo(),
    })
    .to_string();

    // Resolve token. If token starts with '$', read from the named env var.
    // Warn loudly when the variable is unset — silent unauthenticated sends
    // would mean audit events reach the SIEM without any bearer token.
    let resolved_token: Option<String> = config.token.as_ref().and_then(|t| {
        if let Some(var_name) = t.strip_prefix('$') {
            match std::env::var(var_name) {
                Ok(val) if !val.is_empty() => Some(val),
                _ => {
                    eprintln!(
                        "kiteguard: WARNING — webhook token env var '{}' is not set or empty; \
sending event without authentication",
                        var_name
                    );
                    None
                }
            }
        } else {
            Some(t.clone())
        }
    });

    let has_token = resolved_token.as_ref().map(|t| !t.is_empty()).unwrap_or(false);

    // Build curl command using direct CLI arguments.
    //
    // Security rationale:
    // • URL is passed as a positional argument (never embedded in a config-file
    //   format string), eliminating any curl config-file injection risk.
    // • --max-time 3 enforces a hard socket-level timeout so a slow/malicious
    //   endpoint cannot stall the Claude Code pipeline for more than 3 seconds.
    // • The Authorization header is the only value written to -K stdin, and its
    //   content is sanitized to strip newlines/quotes, so there is nothing to
    //   inject into on subsequent config lines.
    use std::process::Stdio;
    let mut cmd = std::process::Command::new("curl");
    cmd.arg("-s")
        .arg("--max-time").arg("3")
        .arg("-X").arg("POST")
        .arg("-H").arg("Content-Type: application/json")
        .arg("-H").arg("User-Agent: kiteguard/0.1.0")
        .arg("--data-raw").arg(&body);

    if has_token {
        // Token via -K stdin keeps it out of `ps aux`.
        cmd.arg("-K").arg("-").stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    // URL as positional argument — never parsed as config-file syntax.
    cmd.arg(&config.url)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return Ok(()), // curl not available — best-effort
    };

    if has_token {
        if let Some(tok) = &resolved_token {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let safe_tok = sanitize_curl_header_value(tok);
                let _ = stdin.write_all(
                    format!("header = \"Authorization: Bearer {}\"\n", safe_tok).as_bytes(),
                );
                // Drop stdin here to signal EOF so curl starts the request.
            }
        }
    }

    // Curl's --max-time 3 provides a hard deadline at the socket level.
    // We poll for up to 4 seconds to reap the process and avoid zombies.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Strips characters that could inject into a curl config-file header value.
/// Used only for the Authorization header value passed via `-K` stdin.
/// - \n / \r : would start a new config-file directive
/// - "       : would terminate the quoted value
/// - \0      : unexpected truncation in C-based config parsing
fn sanitize_curl_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\n' && *c != '\r' && *c != '"' && *c != '\0')
        .collect()
}
