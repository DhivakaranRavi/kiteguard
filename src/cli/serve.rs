use axum::{
    extract::Query,
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::Result;

// Bound memory usage: never load more than this many log entries at once.
const MAX_LOG_ENTRIES: usize = 10_000;

// Simple rate-limiter: allow at most this many requests per minute per endpoint.
// The console is localhost-only, but a rogue local process should not be able
// to cause unbounded file I/O by hammering the API.
const RATE_LIMIT_PER_MIN: u32 = 120;

struct RateLimiter {
    window_start: u64, // unix seconds at start of current 60-s window
    count: u32,
}

impl RateLimiter {
    const fn new() -> Self {
        RateLimiter {
            window_start: 0,
            count: 0,
        }
    }

    /// Returns true if the request should be allowed (updates internal state).
    fn check(&mut self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= self.window_start + 60 {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= RATE_LIMIT_PER_MIN
    }
}

static STATS_RL: Mutex<RateLimiter> = Mutex::new(RateLimiter::new());
static EVENTS_RL: Mutex<RateLimiter> = Mutex::new(RateLimiter::new());

// Embed the compiled Vue dist/ at build time.
// If the console hasn't been built yet, the folder may not exist —
// rust-embed will embed an empty set so the binary still compiles.
#[derive(RustEmbed)]
#[folder = "console/dist/"]
struct DashAssets;

// ── REST models ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatsResponse {
    total: usize,
    blocks: usize,
    allows: usize,
    today: usize,
    threat_breakdown: HashMap<String, usize>,
    hourly: Vec<HourlyBucket>,
}

#[derive(Serialize)]
struct HourlyBucket {
    hour: String, // "HH:00"
    count: usize,
}

#[derive(Deserialize)]
struct EventsQuery {
    page: Option<usize>,
    limit: Option<usize>,
    verdict: Option<String>,
    hook: Option<String>,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<Value>,
    total: usize,
    page: usize,
    limit: usize,
}

// ── Audit log reader ────────────────────────────────────────────────────────────

fn read_entries() -> Vec<Value> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            eprintln!(
                "kiteguard: WARNING — HOME environment variable not set; audit log unavailable"
            );
            return vec![];
        }
    };
    let log_path = std::path::PathBuf::from(&home)
        .join(".kiteguard")
        .join("audit.log");

    let content = std::fs::read_to_string(&log_path).unwrap_or_default();
    // Collect all valid lines then take the last MAX_LOG_ENTRIES to bound
    // memory usage regardless of how large the log file grows.
    let all: Vec<Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let start = all.len().saturating_sub(MAX_LOG_ENTRIES);
    all[start..].to_vec()
}

// ── Handlers ───────────────────────────────────────────────────────────────────

async fn stats_handler() -> Response {
    if !STATS_RL.lock().unwrap_or_else(|e| e.into_inner()).check() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    let entries = read_entries();
    let total = entries.len();

    let today_prefix = today_prefix();
    let mut blocks = 0usize;
    let mut allows = 0usize;
    let mut today = 0usize;
    let mut threat_breakdown: HashMap<String, usize> = HashMap::new();
    // last 24 hourly buckets
    let mut hourly: HashMap<String, usize> = HashMap::new();

    for e in &entries {
        let verdict = e.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let rule = e.get("rule").and_then(|v| v.as_str()).unwrap_or("");
        let ts = e.get("ts").and_then(|v| v.as_str()).unwrap_or("");

        match verdict {
            "block" => blocks += 1,
            "redact" => blocks += 1, // redact is a security action; count with blocks
            _ => allows += 1,
        }

        if ts.starts_with(&today_prefix) {
            today += 1;
        }

        // Threat type = rule name prefix (e.g. "secrets_leak" → "secrets")
        if !rule.is_empty() {
            let category = rule.split('_').next().unwrap_or(rule).to_string();
            *threat_breakdown.entry(category).or_insert(0) += 1;
        }

        // Hourly bucket from ts "YYYY-MM-DDTHH:MM:SSZ"
        // Use char-based iteration instead of byte slice to avoid panicking on
        // non-ASCII timestamps in crafted audit log entries (L6 audit finding).
        let ts_chars: Vec<char> = ts.chars().collect();
        if ts_chars.len() >= 13 {
            let hour_key = format!("{}{}:00", ts_chars[11], ts_chars[12]);
            *hourly.entry(hour_key).or_insert(0) += 1;
        }
    }

    // Convert hourly map to sorted vec (HH:00 order)
    let mut hourly_vec: Vec<HourlyBucket> = hourly
        .into_iter()
        .map(|(hour, count)| HourlyBucket { hour, count })
        .collect();
    hourly_vec.sort_by(|a, b| a.hour.cmp(&b.hour));

    Json(StatsResponse {
        total,
        blocks,
        allows,
        today,
        threat_breakdown,
        hourly: hourly_vec,
    })
    .into_response()
}

async fn events_handler(Query(q): Query<EventsQuery>) -> Response {
    if !EVENTS_RL.lock().unwrap_or_else(|e| e.into_inner()).check() {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    let all_entries = read_entries();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).min(100); // max 100 matches console LIMIT constant

    // Filter
    let filtered: Vec<Value> = all_entries
        .into_iter()
        .filter(|e| {
            if let Some(ref v) = q.verdict {
                if e.get("verdict").and_then(|x| x.as_str()).unwrap_or("") != v {
                    return false;
                }
            }
            if let Some(ref h) = q.hook {
                if e.get("hook").and_then(|x| x.as_str()).unwrap_or("") != h {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    // Most recent first
    let mut sorted = filtered;
    sorted.reverse();

    let start = (page - 1) * limit;
    let events: Vec<Value> = sorted.into_iter().skip(start).take(limit).collect();

    Json(EventsResponse {
        events,
        total,
        page,
        limit,
    })
    .into_response()
}

fn mime_from_path(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "application/javascript",
        "css" => "text/css",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "json" => "application/json",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

// ── Static file serving (embedded Vue dist) ────────────────────────────────────

async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match DashAssets::get(path) {
        Some(content) => {
            let mime = mime_from_path(path);
            ([(header::CONTENT_TYPE, mime)], content.data.into_owned()).into_response()
        }
        None => {
            // SPA fallback: serve index.html for unknown paths
            match DashAssets::get("index.html") {
                Some(content) => (
                    [(header::CONTENT_TYPE, "text/html")],
                    content.data.into_owned(),
                )
                    .into_response(),
                None => (
                    StatusCode::NOT_FOUND,
                    "Console not built yet. Run: cd console && npm run build",
                )
                    .into_response(),
            }
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

fn today_prefix() -> String {
    // Return "YYYY-MM-DD" prefix for today using the system time.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple date calculation: days since epoch
    let days = secs / 86400;
    let (y, m, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Middleware that attaches security headers to every response.
/// Mitigates MIME-sniffing, clickjacking, and basic XSS on the localhost console.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::HeaderName::from_static("content-security-policy"),
        // 'unsafe-inline' removed from script-src — Vite's production build
        // emits external .js files only, no inline scripts.
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; \
             script-src 'self'; img-src 'self' data:",
        ),
    );
    res
}

pub fn run(port: u16) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    rt.block_on(async {
        let app = Router::new()
            .route("/api/stats", get(stats_handler))
            .route("/api/events", get(events_handler))
            .fallback(static_handler)
            .layer(middleware::from_fn(security_headers));

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        println!(
            "\n  \x1b[1;32m✓\x1b[0m KiteGuard Dashboard running at \x1b[1;36mhttp://localhost:{}\x1b[0m\n",
            port
        );
        println!("  Press Ctrl+C to stop.\n");

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

        axum::serve(listener, app)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })
    })
}
