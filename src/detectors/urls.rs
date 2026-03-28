use crate::audit::webhook::SSRF_BLOCKED;
use crate::engine::verdict::Verdict;

/// Scans a URL against the configured domain blocklist.
/// Also catches SSRF attempts targeting cloud metadata endpoints.
/// Hardcoded SSRF targets are shared with the webhook module via SSRF_BLOCKED.
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

    // Hardcoded SSRF protections (cannot be disabled via config)
    for target in SSRF_BLOCKED {
        if url_lower.contains(target) {
            return Some(Verdict::block(
                "ssrf_metadata_endpoint",
                format!(
                    "SSRF attempt blocked — access to cloud metadata endpoint: `{}`",
                    target
                ),
            ));
        }
    }

    None
}
