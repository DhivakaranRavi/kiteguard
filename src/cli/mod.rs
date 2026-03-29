pub mod audit;
pub mod init;
pub mod policy;
pub mod serve;

use crate::error::Result;

/// Entry point for CLI subcommands (when not invoked as a hook)
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("init") => init::run(),
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
kiteguard — Runtime security guardrails for Claude Code

USAGE:
    kiteguard <COMMAND>

COMMANDS:
    init              Register kiteguard hooks with Claude Code
    audit             View the local audit log
    audit verify      Verify audit log chain integrity (detect tampering)
    policy            View active security policies
    policy sign       Re-sign rules.json after manual edits
    serve [PORT]      Start the local dashboard (default port: 7070)
    --version         Print version

HOOKS (invoked automatically by Claude Code):
    Set CLAUDE_HOOK_EVENT=UserPromptSubmit|PreToolUse|PostToolUse|Stop
"#
    );
}
