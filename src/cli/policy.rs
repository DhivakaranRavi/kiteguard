use crate::engine::policy;
use anyhow::Result;

/// kiteguard policy — view and manage active policies
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => list(),
        Some("path") => {
            println!("{}", policy::config_path().display());
            Ok(())
        }
        Some(cmd) => {
            eprintln!("Unknown policy command: {}", cmd);
            eprintln!("Usage: kiteguard policy [list|path]");
            Ok(())
        }
    }
}

fn list() -> Result<()> {
    let p = policy::load()?;
    let config_path = policy::config_path();

    if config_path.exists() {
        println!("Policy loaded from: {}\n", config_path.display());
    } else {
        println!(
            "Using built-in defaults (no rules.yaml found at {})\n",
            config_path.display()
        );
    }

    println!(
        "Bash protection:        {}",
        if p.bash.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("  Block patterns:       {}", p.bash.block_patterns.len());
    println!("  Fail-closed:          {}", p.bash.block_on_error);

    println!("\nFile path protection:");
    println!("  Blocked reads:        {}", p.file_paths.block_read.len());
    println!("  Blocked writes:       {}", p.file_paths.block_write.len());

    println!("\nPII detection:");
    println!("  Block in prompt:      {}", p.pii.block_in_prompt);
    println!("  Block in files:       {}", p.pii.block_in_file_content);
    println!("  Redact in response:   {}", p.pii.redact_in_response);
    println!("  Active types:         {}", p.pii.types.join(", "));

    println!(
        "\nInjection detection:    {}",
        if p.injection.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    println!(
        "\nURL blocklist:          {} entries",
        p.urls.blocklist.len()
    );

    println!("\nWebhook:");
    match p.webhook {
        Some(ref w) if w.enabled => println!("  Enabled → {}", w.url),
        _ => println!("  Disabled (local-only mode)"),
    }

    Ok(())
}
