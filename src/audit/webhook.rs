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
/// Applied iteratively until idempotent to handle double-encoded inputs like
/// `127%252e0%252e0%252e1` (%25 → %, then %2e → .).
fn percent_decode_host(s: &str) -> String {
    let mut current = s.to_string();
    loop {
        let decoded = percent_decode_once(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn percent_decode_once(s: &str) -> String {
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
                || o[0] >= 224 // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
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

    // Enforce HTTPS — webhook body contains identity metadata (user, host, repo).
    // Sending over plain HTTP exposes that data to network interception.
    if !config.url.starts_with("https://") {
        eprintln!(
            "kiteguard: ERROR — webhook URL must use HTTPS to protect audit metadata \
(user/host/repo). Refusing to send over plaintext HTTP. \
Update 'webhook.url' in your policy to start with 'https://'."
        );
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
    // Abort the send when the variable is unset — sending without a bearer
    // token would mean unauthenticated audit events reaching the SIEM.
    let resolved_token: Option<String> = match config.token.as_deref() {
        None => None,
        Some(t) => {
            if let Some(var_name) = t.strip_prefix('$') {
                match std::env::var(var_name) {
                    Ok(val) if !val.is_empty() => Some(val),
                    _ => {
                        eprintln!(
                            "kiteguard: ERROR — webhook token env var '{}' is not set or empty; \
aborting webhook send to prevent unauthenticated audit event transmission. \
Set the '{}' environment variable or remove the token field from your webhook config.",
                            var_name, var_name
                        );
                        return Ok(());
                    }
                }
            } else {
                Some(t.to_string())
            }
        }
    };

    // Compute HMAC-SHA256 signature over the request body if hmac_secret is configured.
    // `hmac_secret` supports `$ENV_VAR` indirection (same convention as `token`).
    let hmac_sig: Option<String> = config.hmac_secret.as_deref().and_then(|raw| {
        let secret = if let Some(var) = raw.strip_prefix('$') {
            std::env::var(var).ok().filter(|v| !v.is_empty())?
        } else {
            raw.to_string()
        };
        Some(hmac_sha256_hex(secret.as_bytes(), body.as_bytes()))
    });

    let has_token = resolved_token
        .as_ref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    // Resolve curl to an absolute path so $PATH cannot be hijacked (H-2).
    // Check canonical locations including Homebrew (Apple Silicon / Intel Mac)
    // and MacPorts; abort silently (best-effort) if absent.
    let curl_path = if std::path::Path::new("/usr/bin/curl").exists() {
        std::path::PathBuf::from("/usr/bin/curl")
    } else if std::path::Path::new("/usr/local/bin/curl").exists() {
        std::path::PathBuf::from("/usr/local/bin/curl")
    } else if std::path::Path::new("/opt/homebrew/bin/curl").exists() {
        std::path::PathBuf::from("/opt/homebrew/bin/curl")
    } else if std::path::Path::new("/opt/local/bin/curl").exists() {
        std::path::PathBuf::from("/opt/local/bin/curl")
    } else {
        return Ok(()); // curl not available — best-effort
    };

    // Write the request body to a private temp file so it never appears in
    // /proc/<pid>/cmdline or `ps aux` output (H-1).
    // The file is created with mode 0o600 (owner-readable only).
    let tmp_path =
        std::env::temp_dir().join(format!("kiteguard-webhook-{}.json", std::process::id()));
    {
        use std::io::Write as _;
        let open_result: std::io::Result<std::fs::File> = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp_path)
            }
            #[cfg(not(unix))]
            {
                std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp_path)
            }
        };
        match open_result {
            Ok(mut f) => {
                if f.write_all(body.as_bytes()).is_err() {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }

    // Build curl command using direct CLI arguments.
    //
    // Security rationale:
    // • Absolute curl path — not resolved via $PATH (H-2 fix).
    // • Body passed via --data @<file> — never in argv (H-1 fix).
    // • URL is a positional argument (never embedded in config-file syntax).
    // • --max-time 3 caps socket-level blocking to 3 seconds.
    // • Authorization is passed via -K stdin (sanitized header value only).
    use std::process::Stdio;
    let mut cmd = std::process::Command::new(&curl_path);
    cmd.arg("-s")
        .arg("--max-time")
        .arg("3")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg("User-Agent: kiteguard/0.1.0");

    // Add HMAC-SHA256 signature header when configured (v0.4 enterprise feature).
    if let Some(ref sig) = hmac_sig {
        cmd.arg("-H")
            .arg(format!("X-KiteGuard-Signature: sha256={}", sig));
    }

    cmd.arg("--data").arg(format!("@{}", tmp_path.display()));

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
        Err(_) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Ok(()); // curl not available — best-effort
        }
    };

    if has_token {
        if let Some(tok) = &resolved_token {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let safe_tok = sanitize_curl_header_value(tok);
                if let Err(e) = stdin.write_all(
                    format!("header = \"Authorization: Bearer {}\"\n", safe_tok).as_bytes(),
                ) {
                    // Broken pipe or other write error — kill the child so it
                    // doesn't silently send an unauthenticated request.
                    eprintln!(
                        "kiteguard: WARNING — failed to write auth token to curl stdin: {}; \
abort webhook send",
                        e
                    );
                    let _ = child.kill();
                    let _ = std::fs::remove_file(&tmp_path);
                    return Ok(());
                }
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

    // Remove the temp body file now that curl has finished (or been killed).
    let _ = std::fs::remove_file(&tmp_path);
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

/// Computes HMAC-SHA256(key, message) and returns the lowercase hex digest.
/// Used to sign outbound webhook payloads (X-KiteGuard-Signature header).
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize();
    result
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_ssrf_safe: safe URLs ---

    #[test]
    fn safe_public_url_allowed() {
        assert!(is_ssrf_safe("https://example.com/api"));
    }

    #[test]
    fn safe_github_allowed() {
        assert!(is_ssrf_safe("https://github.com/rust-lang/rust"));
    }

    // --- is_ssrf_safe: blocked by hostname string-match ---

    #[test]
    fn blocks_aws_metadata_by_hostname() {
        assert!(!is_ssrf_safe("http://169.254.169.254/latest/meta-data/"));
    }

    #[test]
    fn blocks_gcp_metadata_by_hostname() {
        assert!(!is_ssrf_safe(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn blocks_localhost() {
        assert!(!is_ssrf_safe("http://localhost:8080/"));
    }

    #[test]
    fn blocks_ipv6_loopback_bracket() {
        assert!(!is_ssrf_safe("http://[::1]/admin"));
    }

    // --- is_ssrf_safe: blocked by IP-level CIDR ---

    #[test]
    fn blocks_loopback_standard() {
        assert!(!is_ssrf_safe("http://127.0.0.1/"));
    }

    #[test]
    fn blocks_loopback_hex() {
        assert!(!is_ssrf_safe("http://0x7f000001/"));
    }

    #[test]
    fn blocks_loopback_decimal_int() {
        assert!(!is_ssrf_safe("http://2130706433/"));
    }

    #[test]
    fn blocks_loopback_octal_dotted() {
        assert!(!is_ssrf_safe("http://0177.0.0.1/"));
    }

    #[test]
    fn blocks_private_10_range() {
        assert!(!is_ssrf_safe("http://10.0.0.1/"));
    }

    #[test]
    fn blocks_private_172_range() {
        assert!(!is_ssrf_safe("http://172.16.0.1/"));
    }

    #[test]
    fn blocks_private_192_168() {
        assert!(!is_ssrf_safe("http://192.168.1.1/"));
    }

    #[test]
    fn blocks_link_local() {
        assert!(!is_ssrf_safe("http://169.254.1.1/"));
    }

    // --- is_ssrf_safe: percent-encoded bypass attempts ---

    #[test]
    fn blocks_percent_encoded_loopback() {
        assert!(!is_ssrf_safe("http://127%2e0%2e0%2e1/"));
    }

    #[test]
    fn blocks_double_percent_encoded_loopback() {
        assert!(!is_ssrf_safe("http://127%252e0%252e0%252e1/"));
    }

    // --- sanitize_curl_header_value ---

    #[test]
    fn sanitize_strips_newline() {
        assert_eq!(
            sanitize_curl_header_value("tok\nheader:evil"),
            "tokheader:evil"
        );
    }

    #[test]
    fn sanitize_strips_carriage_return() {
        assert_eq!(sanitize_curl_header_value("tok\rheader"), "tokheader");
    }

    #[test]
    fn sanitize_strips_null_byte() {
        assert_eq!(sanitize_curl_header_value("tok\0abc"), "tokabc");
    }

    #[test]
    fn sanitize_strips_quotes() {
        assert_eq!(sanitize_curl_header_value("to\"ken"), "token");
    }

    #[test]
    fn sanitize_clean_token_unchanged() {
        assert_eq!(sanitize_curl_header_value("mytoken123"), "mytoken123");
    }

    // --- hmac_sha256_hex ---

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test vector #1: key=0x0b*20, data="Hi There"
        let key = vec![0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha256_hex(&key, msg);
        assert_eq!(
            result,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
