use crate::error::Result;
use serde_json::Value;
use std::fs;

/// kiteguard init — registers all hooks in ~/.claude/settings.json
pub fn run() -> Result<()> {
    let binary_path = current_binary_path()?;
    let settings_path = crate::util::home_dir()
        .join(".claude")
        .join("settings.json");

    // Read existing settings or start fresh
    let mut settings: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)
            .map_err(|e| format!("Failed to read ~/.claude/settings.json: {}", e))?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Inject kiteguard hooks
    let hooks = serde_json::json!({
        "UserPromptSubmit": [{ "command": binary_path }],
        "PreToolUse":       [{ "command": binary_path }],
        "PostToolUse":      [{ "command": binary_path }],
        "Stop":             [{ "command": binary_path }]
    });

    settings["hooks"] = hooks;

    // Write back
    fs::create_dir_all(settings_path.parent().unwrap())?;
    fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;

    // Restrict settings file to owner-only read/write (chmod 600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&settings_path, std::fs::Permissions::from_mode(0o600));
    }

    // Create default config dir and lock it down (chmod 700)
    let config_dir = crate::util::home_dir().join(".kiteguard");
    fs::create_dir_all(&config_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700));
    }

    println!("kiteguard initialized successfully!");
    println!("  Hooks registered in: {}", settings_path.display());
    println!("  Config directory:     {}", config_dir.display());
    println!(
        "  Audit log:            {}",
        config_dir.join("audit.log").display()
    );
    println!("\nEvery Claude Code session is now guarded.");

    Ok(())
}

fn current_binary_path() -> Result<String> {
    std::env::current_exe()
        .map_err(|e| format!("Could not determine kiteguard binary path: {}", e))?
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Binary path is not valid UTF-8".into())
}
