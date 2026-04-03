pub mod audit;
pub mod init;
pub mod policy;
pub mod serve;

use crate::error::Result;

/// Entry point for CLI subcommands (when not invoked as a hook)
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("init") => {
            match args.get(2).map(|s| s.as_str()) {
                Some("--claude-code") => init::run(),
                Some("--cursor")      => init::run_cursor(),
                Some("--gemini")     => {
                    let verbose = args.iter().any(|a| a == "--verbose");
                    init::run_gemini(verbose)
                }
                _ => {
                    eprintln!("Usage: kiteguard init --claude-code | --cursor | --gemini [--verbose]");
                    eprintln!();
                    eprintln!("  --claude-code   Register hooks in ~/.claude/settings.json");
                    eprintln!("  --cursor        Register hooks for Cursor (.cursor/hooks.json)");
                    eprintln!("  --gemini        Register hooks for Gemini CLI");
                    std::process::exit(1);
                }
            }
        }
        Some("serve") => {
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7070);
            serve::run(port)
        }
        Some("audit") => {
            if args.get(2).map(|s| s.as_str()) == Some("verify") {
                audit::verify()
            } else {
                audit::run()
            }
        }
        Some("policy") => policy::run(&args[2..]),
        Some("--version") | Some("-V") => {
            println!("kiteguard {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        r#"
kiteguard — Runtime security guardrails for Claude Code, GitHub Copilot, and Gemini CLI

USAGE:
    kiteguard <COMMAND>

COMMANDS:
    init --claude-code           Register kiteguard hooks with Claude Code
    init --cursor                Register kiteguard hooks with Cursor
    init --gemini                Register kiteguard hooks with Gemini CLI
    init --gemini --verbose      Register Gemini hooks with KITEGUARD_VERBOSE=1 baked in
    audit                    View the local audit log
    audit verify             Verify audit log chain integrity (detect tampering)
    policy                   View active security policies
    policy sign              Re-sign rules.json after manual edits
    serve [PORT]             Start the local dashboard (default port: 7070)
    --version                Print version

HOOKS (invoked automatically by the active agent runtime):
    Claude Code:     CLAUDE_HOOK_EVENT=UserPromptSubmit|PreToolUse|PostToolUse|Stop
    Cursor:          CURSOR_PROJECT_DIR env var + hook_event_name in JSON payload (camelCase)
    Gemini CLI:      hook_event_name in JSON payload (snake_case)

ENVIRONMENT:
    KITEGUARD_VERBOSE=1      Print step-by-step trace to stderr showing client
                             detection, policy loaded, each detector run, and
                             the final verdict. Output goes to stderr only and
                             never affects the JSON stdout responses.
"#
    );
}
