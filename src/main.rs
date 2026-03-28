mod audit;
mod cli;
mod detectors;
mod engine;
mod hooks;

use anyhow::Result;
use std::io::{self, Read};

fn main() -> Result<()> {
    let hook_event = std::env::var("CLAUDE_HOOK_EVENT").unwrap_or_default();

    // CLI subcommands when not invoked as a hook
    if hook_event.is_empty() {
        return cli::run();
    }

    // Read JSON payload from stdin (Claude Code passes it here)
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    // Load policy config
    let policy = engine::policy::load()?;

    // Dispatch to the correct hook handler
    let verdict = match hook_event.as_str() {
        "UserPromptSubmit" => hooks::pre_prompt::handle(&input, &policy),
        "PreToolUse"       => hooks::pre_tool::handle(&input, &policy),
        "PostToolUse"      => hooks::post_tool::handle(&input, &policy),
        "Stop"             => hooks::post_response::handle(&input, &policy),
        _                  => Ok(engine::verdict::Verdict::Allow),
    };

    let verdict = verdict.unwrap_or_else(|_| {
        // Fail-closed: if kiteguard crashes, block the action
        engine::verdict::Verdict::Block {
            rule: "internal_error".into(),
            reason: "kiteguard encountered an internal error — action blocked (fail-closed)".into(),
        }
    });

    // Log every event to audit log
    audit::logger::log(&hook_event, &input, &verdict)?;

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
