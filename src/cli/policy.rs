use crate::engine::policy;
use crate::error::Result;

/// kiteguard policy — view and manage active policies
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => list(),
        Some("path") => {
            println!("{}", policy::config_path().display());
            Ok(())
        }
        Some("sign") => sign(),
        Some(cmd) => {
            eprintln!("Unknown policy command: {}", cmd);
            eprintln!("Usage: kiteguard policy [list|path|sign]");
            Ok(())
        }
    }
}

fn sign() -> Result<()> {
    let config_dir = crate::util::home_dir().join(".kiteguard");
    let key_path = config_dir.join(".key");

    if !key_path.exists() {
        eprintln!("No signing key found. Run 'kiteguard init' first to generate the key.");
        std::process::exit(1);
    }

    crate::cli::init::sign_policy(&config_dir)?;

    let rules_path = config_dir.join("rules.json");
    let sig_path = config_dir.join("policy.sig");
    println!("Policy signed.");
    if rules_path.exists() {
        println!("  Policy:    {}", rules_path.display());
    } else {
        println!("  Policy:    built-in defaults (no rules.json)");
    }
    println!("  Signature: {}", sig_path.display());
    println!("\nRun this after any manual changes to rules.json.");
    Ok(())
}

fn list() -> Result<()> {
    let p = policy::load()?;
    let config_path = policy::config_path();

    if config_path.exists() {
        println!("Policy loaded from: {}\n", config_path.display());
    } else {
        println!(
            "Using built-in defaults (no rules.json found at {})\n",
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
