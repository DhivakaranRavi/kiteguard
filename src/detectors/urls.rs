use crate::audit::webhook;
use crate::engine::verdict::Verdict;

/// Extracts the lowercase hostname from a URL without an external crate.
/// "https://user@Evil.COM:8080/path?q=1" → "evil.com"
/// Returns an empty string if the URL is malformed.
fn extract_host(url: &str) -> String {
    // Drop scheme (e.g. "https://")
    let after_scheme = if let Some(i) = url.find("://") {
        &url[i + 3..]
    } else {
        url
    };
    // Drop userinfo ("user@")
    let authority = if let Some(at) = after_scheme.find('@') {
        &after_scheme[at + 1..]
    } else {
        after_scheme
    };
    // Drop path / query / fragment
    let host_and_port = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    // Handle IPv6 bracketed addresses (e.g. "[::1]:8080")
    if host_and_port.starts_with('[') {
        return host_and_port
            .find(']')
            .map(|end| host_and_port[1..end].to_lowercase())
            .unwrap_or_default();
    }
    // Drop port
    host_and_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_and_port)
        .to_lowercase()
}

/// Scans prompt text for any URL that matches the blocklist or is an SSRF target.
/// Extracts http/https/ftp URLs from the prompt and checks each one.
pub fn scan_prompt(prompt: &str, blocklist: &[String]) -> Option<Verdict> {
    // Extract tokens that look like URLs
    for token in
        prompt.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | '<' | '>'))
    {
        let token = token.trim_matches(|c: char| matches!(c, '.' | ')' | ']'));
        if (token.starts_with("http://")
            || token.starts_with("https://")
            || token.starts_with("ftp://"))
            && scan(token, blocklist).is_some()
        {
            return Some(Verdict::block(
                "blocked_url_in_prompt",
                format!("Prompt references a blocked URL: `{}`", token),
            ));
        }
    }
    None
}

/// Scans a URL against the configured domain blocklist.
/// Also catches SSRF attempts — two layers:
///   1. String-match against known hostname/metadata strings (SSRF_BLOCKED).
///   2. IP-level CIDR check (handles hex/octal/decimal-int/IPv4-mapped-IPv6
///      encodings that bypass naive string matching, e.g. 0x7f000001,
///      0177.0.0.1, 2130706433 all equal 127.0.0.1).
pub fn scan(url: &str, blocklist: &[String]) -> Option<Verdict> {
    let host = extract_host(url);

    // Blocklist matching: exact hostname or subdomain suffix.
    // e.g. "evil.com" blocks "evil.com" and "sub.evil.com" but NOT
    // "notevil.com" or "evil.com.attacker.net".
    for blocked in blocklist {
        let blocked_lower = blocked.to_lowercase();
        if host == blocked_lower || host.ends_with(&format!(".{}", blocked_lower)) {
            return Some(Verdict::block(
                "blocked_url",
                format!("Request to blocked domain blocked: `{}`", blocked),
            ));
        }
    }

    // Hardcoded SSRF protections — string match + full IP-level check.
    // is_ssrf_safe() covers both layers so alternate IP encodings cannot
    // bypass the check the way a string-only match would.
    if !webhook::is_ssrf_safe(url) {
        return Some(Verdict::block(
            "ssrf_metadata_endpoint",
            format!(
                "SSRF attempt blocked — access to private/metadata endpoint: `{}`",
                url
            ),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bl(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // --- extract_host ---

    #[test]
    fn extract_host_simple() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(extract_host("https://example.com:8080/path"), "example.com");
    }

    #[test]
    fn extract_host_with_userinfo() {
        assert_eq!(extract_host("https://user@Evil.COM/"), "evil.com");
    }

    #[test]
    fn extract_host_ipv6_bracketed() {
        assert_eq!(extract_host("http://[::1]:80/"), "::1");
    }

    #[test]
    fn extract_host_strips_query_fragment() {
        assert_eq!(extract_host("http://host.com/path?q=1#frag"), "host.com");
    }

    #[test]
    fn extract_host_lowercases() {
        assert_eq!(extract_host("https://UPPER.COM"), "upper.com");
    }

    // --- blocklist matching: exact + subdomain ---

    #[test]
    fn blocks_exact_domain() {
        assert!(scan("https://evil.com/page", &bl(&["evil.com"])).is_some());
    }

    #[test]
    fn blocks_subdomain_of_blocked() {
        assert!(scan("https://sub.evil.com/page", &bl(&["evil.com"])).is_some());
    }

    #[test]
    fn no_false_positive_on_suffix_without_dot() {
        // "notevil.com" must NOT match a block on "evil.com"
        assert!(scan("https://notevil.com/page", &bl(&["evil.com"])).is_none());
    }

    #[test]
    fn no_false_positive_attacker_domain_with_blocked_as_subdomain() {
        // "evil.com.attacker.net" must NOT match a block on "evil.com"
        assert!(scan("https://evil.com.attacker.net/", &bl(&["evil.com"])).is_none());
    }

    #[test]
    fn empty_blocklist_with_safe_url_allows() {
        assert!(scan("https://github.com/repo", &[]).is_none());
    }

    // --- SSRF protection ---

    #[test]
    fn blocks_aws_metadata() {
        assert!(scan("http://169.254.169.254/latest/meta-data/", &[]).is_some());
    }

    #[test]
    fn blocks_localhost() {
        assert!(scan("http://localhost/admin", &[]).is_some());
    }

    #[test]
    fn blocks_loopback_127() {
        assert!(scan("http://127.0.0.1/", &[]).is_some());
    }

    #[test]
    fn blocks_hex_encoded_loopback() {
        assert!(scan("http://0x7f000001/", &[]).is_some());
    }

    #[test]
    fn blocks_decimal_int_loopback() {
        assert!(scan("http://2130706433/", &[]).is_some());
    }

    #[test]
    fn blocks_octal_loopback() {
        assert!(scan("http://0177.0.0.1/", &[]).is_some());
    }

    #[test]
    fn blocks_percent_encoded_loopback() {
        assert!(scan("http://127%2e0%2e0%2e1/", &[]).is_some());
    }

    // --- scan_prompt ---

    #[test]
    fn scan_prompt_detects_ssrf_url_in_text() {
        let result = scan_prompt("Please fetch http://169.254.169.254/latest/meta-data/", &[]);
        assert!(result.is_some());
    }

    #[test]
    fn scan_prompt_allows_safe_url_in_text() {
        let result = scan_prompt("See https://docs.rs/regex for docs", &[]);
        assert!(result.is_none());
    }
}
