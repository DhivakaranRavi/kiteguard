mod audit;
mod cli;
mod crypto;
mod detectors;
mod engine;
mod error;
mod hooks;
mod util;

use error::Result;
use std::io::{self, Read};

fn main() -> Result<()> {
    let hook_event = std::env::var("CLAUDE_HOOK_EVENT").unwrap_or_default();

    // CLI subcommands when not invoked as a hook
    if hook_event.is_empty() {
        return cli::run();
    }

    // Read JSON payload from stdin (Claude Code passes it here).
    // Cap at 10 MB to prevent memory exhaustion from crafted payloads.
    const MAX_PAYLOAD: u64 = 10 * 1024 * 1024;
    let mut input = String::new();
    io::stdin().take(MAX_PAYLOAD).read_to_string(&mut input)?;

    // Load policy config.
    // Fail-closed on tamper: if signature is present but doesn't match,
    // block the Claude action (exit 2) rather than proceeding with untrusted policy.
    let policy = match engine::policy::load() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\n[kiteguard] POLICY ERROR: {}\n", e);
            std::process::exit(2);
        }
    };

    // Dispatch to the correct hook handler
    let verdict = match hook_event.as_str() {
        "UserPromptSubmit" => hooks::pre_prompt::handle(&input, &policy),
        "PreToolUse" => hooks::pre_tool::handle(&input, &policy),
        "PostToolUse" => hooks::post_tool::handle(&input, &policy),
        "Stop" => hooks::post_response::handle(&input, &policy),
        _ => Ok(engine::verdict::Verdict::Allow),
    };

    let verdict = verdict.unwrap_or_else(|_| {
        // Fail-closed: if kiteguard crashes, block the action
        engine::verdict::Verdict::Block {
            rule: "internal_error".into(),
            reason: "kiteguard encountered an internal error — action blocked (fail-closed)".into(),
        }
    });

    // Log every event to audit log.
    // Non-fatal: a disk-full or permission error must NOT prevent verdict
    // enforcement — a block verdict would silently escape as exit code 1
    // (Rust error) rather than exit code 2 (Claude Code block signal).
    if let Err(e) = audit::logger::log(&hook_event, &input, &verdict) {
        eprintln!(
            "[kiteguard] audit log failed ({}); continuing to enforce verdict",
            e
        );
    }

    // Optionally send to webhook
    if let Some(ref webhook) = policy.webhook {
        if webhook.enabled {
            let _ = audit::webhook::send(webhook, &hook_event, &verdict);
        }
    }

    // Exit with correct code for Claude Code
    match verdict {
        engine::verdict::Verdict::Allow => std::process::exit(0),
        engine::verdict::Verdict::Block { reason, .. } => {
            eprintln!("\n[kiteguard] BLOCKED: {}\n", reason);
            std::process::exit(2);
        }
        engine::verdict::Verdict::Redact { .. } => std::process::exit(0),
    }
}
