use crate::engine::{evaluator, policy};
use crate::error::Result;

/// `kiteguard test` — run a sample input through the active policy and show
/// exactly what verdict would be returned, without blocking any tool.
///
/// Usage:
///   kiteguard test prompt  "<text>"
///   kiteguard test command "<bash command>"
///   kiteguard test read    "<file path>"
///   kiteguard test write   "<file path>"
///   kiteguard test url     "<url>"
pub fn run(args: &[String]) -> Result<()> {
    let kind = args.first().map(|s| s.as_str()).unwrap_or("");
    let input = args.get(1).map(|s| s.as_str()).unwrap_or("");

    if kind.is_empty() || input.is_empty() {
        eprintln!("Usage: kiteguard test <type> <input>");
        eprintln!();
        eprintln!("Types:");
        eprintln!("  prompt   \"<user prompt text>\"");
        eprintln!("  command  \"<bash command>\"");
        eprintln!("  read     \"<file path>\"");
        eprintln!("  write    \"<file path>\"");
        eprintln!("  url      \"<url>\"");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  kiteguard test command \"rm -rf /\"");
        eprintln!("  kiteguard test read    \"~/.ssh/id_rsa\"");
        eprintln!("  kiteguard test url     \"https://169.254.169.254/latest/meta-data\"");
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
            // Exit 2 mirrors the real hook behaviour so scripts can detect blocks.
            std::process::exit(2);
        }
        Verdict::Redact { original, redacted } => {
            println!("~  REDACT");
            println!("   type:     {}", kind);
            println!("   original: {}", original);
            println!("   redacted: {}", redacted);
        }
    }

    Ok(())
}
