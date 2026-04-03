use crate::engine::{evaluator, policy};
use crate::error::Result;

/// `kiteguard test` — run a sample input through the active policy and show
/// exactly what verdict would be returned, without blocking any tool.
///
/// Usage:
///   kiteguard test [--json] <type> <input>
///
///   kiteguard test prompt  "<text>"
///   kiteguard test command "<bash command>"
///   kiteguard test read    "<file path>"
///   kiteguard test write   "<file path>"
///   kiteguard test url     "<url>"
///
///   kiteguard test --json command "rm -rf /"   # machine-readable output
pub fn run(args: &[String]) -> Result<()> {
    // Parse optional --json flag
    let json_out = args.first().map(|s| s == "--json").unwrap_or(false);
    let rest: &[String] = if json_out { &args[1..] } else { args };

    let kind = rest.first().map(|s| s.as_str()).unwrap_or("");
    let input = rest.get(1).map(|s| s.as_str()).unwrap_or("");

    if kind.is_empty() || input.is_empty() {
        eprintln!("Usage: kiteguard test [--json] <type> <input>");
        eprintln!();
        eprintln!("Types:");
        eprintln!("  prompt   \"<user prompt text>\"");
        eprintln!("  command  \"<bash command>\"");
        eprintln!("  read     \"<file path>\"");
        eprintln!("  write    \"<file path>\"");
        eprintln!("  url      \"<url>\"");
        eprintln!();
        eprintln!("Flags:");
        eprintln!("  --json   Output result as a single JSON object");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  kiteguard test command \"rm -rf /\"");
        eprintln!("  kiteguard test read    \"~/.ssh/id_rsa\"");
        eprintln!("  kiteguard test url     \"https://169.254.169.254/latest/meta-data\"");
        eprintln!("  kiteguard test --json command \"rm -rf /\"");
        std::process::exit(1);
    }

    let p = policy::load()?;

    let verdict = match kind {
        "prompt" => evaluator::evaluate_prompt(input, &p),
        "command" => evaluator::evaluate_command(input, &p),
        "read" => evaluator::evaluate_file_read(input, &p),
        "write" => evaluator::evaluate_file_write(input, &p),
        "url" => evaluator::evaluate_url(input, &p),
        other => {
            eprintln!("Unknown test type: {}", other);
            eprintln!("Valid types: prompt, command, read, write, url");
            std::process::exit(1);
        }
    };

    use crate::engine::verdict::Verdict;

    if json_out {
        let obj = match &verdict {
            Verdict::Allow => serde_json::json!({
                "verdict": "allow",
                "type": kind,
                "input": input
            }),
            Verdict::Block { rule, reason } => serde_json::json!({
                "verdict": "block",
                "type": kind,
                "input": input,
                "rule": rule,
                "reason": reason
            }),
            Verdict::Redact { original, redacted } => serde_json::json!({
                "verdict": "redact",
                "type": kind,
                "original": original,
                "redacted": redacted
            }),
        };
        println!("{}", serde_json::to_string(&obj).unwrap_or_default());
    } else {
        match &verdict {
            Verdict::Allow => {
                println!("✓  ALLOW");
                println!("   type:  {}", kind);
                println!("   input: {}", input);
            }
            Verdict::Block { rule, reason } => {
                println!("✗  BLOCK");
                println!("   type:   {}", kind);
                println!("   input:  {}", input);
                println!("   rule:   {}", rule);
                println!("   reason: {}", reason);
            }
            Verdict::Redact { original, redacted } => {
                println!("~  REDACT");
                println!("   type:     {}", kind);
                println!("   original: {}", original);
                println!("   redacted: {}", redacted);
            }
        }
    }

    // Exit 2 on block regardless of output format — lets scripts detect blocks.
    if verdict.is_block() {
        std::process::exit(2);
    }

    Ok(())
}
