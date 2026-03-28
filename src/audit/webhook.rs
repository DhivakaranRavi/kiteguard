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
fn is_ssrf_safe(url: &str) -> bool {
    let lower = url.to_lowercase();

    // Layer 1: known hostname string-match
    for blocked in SSRF_BLOCKED {
        if lower.contains(blocked) {
            return false;
        }
    }

    // Layer 2: IP-level CIDR check (handles encoded/alternate notations)
    if let Some(host) = extract_host(&lower) {
        if let Some(ip) = parse_ip_any(&host) {
            if is_blocked_ip(ip) {
                return false;
            }
        }
    }

    true
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
                || o[0] == 0 // 0.0.0.0/8
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                                        // ::1
                || (v6.segments()[0] & 0xfe00) == 0xfc00            // fc00::/7 ULA (covers fd00::)
                || (v6.segments()[0] & 0xffc0) == 0xfe80            // fe80::/10 link-local
                || match v6.to_ipv4_mapped() {                      // ::ffff:0:0/96
                    Some(v4) => {
                        let o = v4.octets();
                        o[0] == 127
                            || o[0] == 10
                            || (o[0] == 172 && (16..=31).contains(&o[1]))
                            || (o[0] == 192 && o[1] == 168)
                            || (o[0] == 169 && o[1] == 254)
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

    // 5-second timeout — don't stall the Claude pipeline on a slow/down SIEM.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
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
