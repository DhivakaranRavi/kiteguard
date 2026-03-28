use crate::audit::webhook;
use crate::engine::verdict::Verdict;

/// Scans a URL against the configured domain blocklist.
/// Also catches SSRF attempts — two layers:
///   1. String-match against known hostname/metadata strings (SSRF_BLOCKED).
///   2. IP-level CIDR check (handles hex/octal/decimal-int/IPv4-mapped-IPv6
///      encodings that bypass naive string matching, e.g. 0x7f000001,
///      0177.0.0.1, 2130706433 all equal 127.0.0.1).
pub fn scan(url: &str, blocklist: &[String]) -> Option<Verdict> {
    let url_lower = url.to_lowercase();

    for blocked in blocklist {
        if url_lower.contains(&blocked.to_lowercase()) {
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
