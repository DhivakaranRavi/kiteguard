mod audit;
mod cli;
mod crypto;
mod detectors;
mod engine;
mod error;
mod hooks;
mod util;

use error::Result;
use std::io::{self, IsTerminal, Read};

fn main() -> Result<()> {
    let hook_event = std::env::var("CLAUDE_HOOK_EVENT").unwrap_or_default();

    // CLI subcommands when not invoked as a hook (env var absent AND no piped stdin)
    if hook_event.is_empty() && std::env::var("COPILOT_HOOK_EVENT").is_err() {
        // Peek: if stdin is a TTY there's no hook payload coming — run as CLI.
        // If stdin is a pipe (Copilot/Claude passing JSON), we'll detect below.
        if std::io::stdin().is_terminal() {
            return cli::run();
        }
    }

    // Read JSON payload from stdin.
    // Cap at 10 MB to prevent memory exhaustion from crafted payloads.
    const MAX_PAYLOAD: u64 = 10 * 1024 * 1024;
    let mut input = String::new();
    io::stdin().take(MAX_PAYLOAD).read_to_string(&mut input)?;

    // Resolve hook event name:
    //   1. CLAUDE_HOOK_EVENT env var  (Claude Code)
    //   2. COPILOT_HOOK_EVENT env var (future VS Code env injection)
    //   3. "hookEventName" field in the JSON payload (current VS Code Copilot format)
    let hook_event = if !hook_event.is_empty() {
        hook_event
    } else if let Ok(ev) = std::env::var("COPILOT_HOOK_EVENT") {
        ev
    } else {
        // Parse JSON payload for event name:
        //   "hookEventName"     (camelCase)  → VS Code Copilot
        //   "hook_event_name"   (snake_case) → Gemini CLI
        serde_json::from_str::<serde_json::Value>(&input)
            .ok()
            .and_then(|v| {
                v["hookEventName"]
                    .as_str()
                    .or_else(|| v["hook_event_name"].as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default()
    };

    // Detect which AI runtime invoked kiteguard so it can be recorded in the audit log.
    //   - "claude"  → Claude Code (CLAUDE_HOOK_EVENT env var)
    //   - "cursor"  → Cursor (CURSOR_PROJECT_DIR env var set by Cursor for all hooks)
    //   - "gemini"  → Gemini CLI ("hook_event_name" snake_case in JSON payload)
    //   - "copilot" → VS Code Copilot ("hookEventName" camelCase in JSON payload)
    let client = if std::env::var("CLAUDE_HOOK_EVENT").is_ok() {
        "claude"
    } else if std::env::var("COPILOT_HOOK_EVENT").is_ok() {
        "copilot"
    } else if std::env::var("CURSOR_PROJECT_DIR").is_ok() {
        // Cursor sets CURSOR_PROJECT_DIR for every hook invocation.
        // Check before the generic hook_event_name payload detection since
        // Cursor also uses snake_case hook_event_name like Gemini.
        "cursor"
    } else {
        let parsed = serde_json::from_str::<serde_json::Value>(&input).ok();
        if parsed
            .as_ref()
            .and_then(|v| v.get("hook_event_name"))
            .is_some()
        {
            "gemini"
        } else if parsed
            .as_ref()
            .and_then(|v| v.get("hookEventName"))
            .is_some()
        {
            "copilot"
        } else {
            "unknown"
        }
    };
    let is_gemini = client == "gemini";
    let is_cursor = client == "cursor";
    vlog!("client={} event={}", client, hook_event);

    // If we still have no event (e.g. called from CLI without piped input), run as CLI.
    if hook_event.is_empty() {
        return cli::run();
    }

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
    vlog!(
        "policy loaded — injection={} bash={} pii_prompt={} pii_file={} urls={} paths_read={} paths_write={}",
        policy.injection.enabled,
        policy.bash.enabled,
        policy.pii.block_in_prompt,
        policy.pii.block_in_file_content,
        policy.urls.blocklist.len(),
        policy.file_paths.block_read.len(),
        policy.file_paths.block_write.len()
    );

    // Dispatch to the correct hook handler (Claude Code, Cursor, and Gemini CLI)
    let verdict = match hook_event.as_str() {
        // Claude Code events (PascalCase, via CLAUDE_HOOK_EVENT env var)
        "UserPromptSubmit" => hooks::pre_prompt::handle(&input, &policy),
        "PreToolUse" => hooks::pre_tool::handle(&input, &policy),
        "PostToolUse" => hooks::post_tool::handle(&input, &policy),
        "Stop" => hooks::post_response::handle(&input, &policy),
        // Gemini CLI events — mapped to the same underlying handlers
        "BeforeAgent" => hooks::pre_prompt::handle(&input, &policy),
        "BeforeTool" => hooks::pre_tool::handle(&input, &policy),
        "AfterTool" => hooks::post_tool::handle(&input, &policy),
        "AfterAgent" => hooks::post_response::handle(&input, &policy),
        // Cursor events (camelCase, delivered via hook_event_name field)
        "beforeSubmitPrompt" => hooks::pre_prompt::handle(&input, &policy),
        "preToolUse" => hooks::pre_tool::handle(&input, &policy),
        "beforeShellExecution" => hooks::pre_tool::handle_shell_exec(&input, &policy),
        "beforeReadFile" => hooks::pre_tool::handle_read_file(&input, &policy),
        "postToolUse" => hooks::post_tool::handle(&input, &policy),
        "afterShellExecution" => hooks::post_tool::handle_shell_output(&input, &policy),
        "beforeMCPExecution" => hooks::pre_tool::handle_mcp_exec(&input, &policy),
        "afterMCPExecution" => hooks::post_tool::handle_mcp_output(&input, &policy),
        "beforeTabFileRead" => hooks::pre_tool::handle_tab_read(&input, &policy),
        // afterFileEdit carries edit strings, not file content — path check via preToolUse Write
        "afterFileEdit" => Ok(engine::verdict::Verdict::Allow),
        "afterAgentResponse" => hooks::post_response::handle_agent_response(&input, &policy),
        // Cursor stop payload has no transcript; afterAgentResponse covers response scanning
        "stop" => Ok(engine::verdict::Verdict::Allow),
        // Advisory/lifecycle events (all runtimes) — no security action needed
        "SessionStart"
        | "SessionEnd"
        | "PreCompact"
        | "SubagentStart"
        | "SubagentStop"
        | "BeforeModel"
        | "AfterModel"
        | "BeforeToolSelection"
        | "PreCompress"
        | "Notification"
        | "sessionStart"
        | "sessionEnd"
        | "preCompact"
        | "subagentStart"
        | "subagentStop"
        | "postToolUseFailure"
        | "afterAgentThought"
        | "afterTabFileRead"
        | "afterTabFileEdit" => Ok(engine::verdict::Verdict::Allow),
        _ => Ok(engine::verdict::Verdict::Allow),
    };

    let verdict = verdict.unwrap_or_else(|_| {
        // Fail-closed: if kiteguard crashes, block the action
        engine::verdict::Verdict::Block {
            rule: "internal_error".into(),
            reason: "kiteguard encountered an internal error — action blocked (fail-closed)".into(),
        }
    });
    match &verdict {
        engine::verdict::Verdict::Allow => vlog!("verdict → allow"),
        engine::verdict::Verdict::Redact { .. } => vlog!("verdict → redact"),
        engine::verdict::Verdict::Block { rule, reason } => {
            vlog!("verdict → BLOCK  rule={}  reason={}", rule, reason)
        }
    }

    // Log every event to audit log.
    // Non-fatal: a disk-full or permission error must NOT prevent verdict
    // enforcement — a block verdict would silently escape as exit code 1
    // (Rust error) rather than exit code 2 (Claude Code block signal).
    if let Err(e) = audit::logger::log(&hook_event, &input, &verdict, client) {
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

    // Emit verdict output appropriate to the active runtime.
    // Gemini CLI: exit 0 + JSON stdout {"decision":"deny"} is the preferred block path.
    // Claude Code + Cursor: exit code 2 signals a block to the host.
    // Cursor also accepts exit code 2 as equivalent to permission: "deny" for all hook types.
    match verdict {
        engine::verdict::Verdict::Allow | engine::verdict::Verdict::Redact { .. } => {
            if is_gemini || is_cursor {
                println!("{{}}");
            }
            std::process::exit(0);
        }
        engine::verdict::Verdict::Block { reason, .. } => {
            eprintln!("\n[kiteguard] BLOCKED: {}\n", reason);
            if is_gemini {
                // Gemini CLI: exit 0 + JSON stdout {"decision":"deny"} is the preferred block path
                let out = serde_json::json!({"decision": "deny", "reason": reason});
                println!("{}", out);
                std::process::exit(0);
            } else {
                // Claude Code + Cursor: exit code 2 blocks the action
                std::process::exit(2);
            }
        }
    }
}
