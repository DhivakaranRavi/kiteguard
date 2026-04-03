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
    let parent = settings_path
        .parent()
        .ok_or("~/.claude/settings.json has no parent directory")?;
    fs::create_dir_all(parent)?;
    fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;

    // Restrict settings file to owner-only read/write (chmod 600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&settings_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!(
                "kiteguard: WARNING — could not restrict {} permissions: {}. \
Manually run: chmod 600 {}",
                settings_path.display(),
                e,
                settings_path.display()
            );
        }
    }

    // Create default config dir and lock it down (chmod 700)
    let config_dir = crate::util::home_dir().join(".kiteguard");
    fs::create_dir_all(&config_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700))
        {
            eprintln!(
                "kiteguard: WARNING — could not restrict {} permissions: {}. \
Manually run: chmod 700 {}",
                config_dir.display(),
                e,
                config_dir.display()
            );
        }
    }

    // Generate signing key (if none exists) and sign the current policy.
    // This establishes the integrity baseline — any future tampering is detected.
    sign_policy(&config_dir)?;

    println!("kiteguard initialized successfully!");
    println!("  Hooks registered in: {}", settings_path.display());
    println!("  Config directory:     {}", config_dir.display());
    println!(
        "  Audit log:            {}",
        config_dir.join("audit.log").display()
    );
    println!(
        "  Policy signature:     {}",
        config_dir.join("policy.sig").display()
    );
    println!("\nEvery Claude Code session is now guarded.");
    println!("After editing rules.json, run: kiteguard policy sign");

    Ok(())
}

/// Generates a signing key (if absent) and writes HMAC-SHA256 of the current
/// rules.json content (or empty string for default policy) to policy.sig.
pub fn sign_policy(config_dir: &std::path::Path) -> Result<()> {
    let key_path = config_dir.join(".key");
    let rules_path = config_dir.join("rules.json");
    let rules_content = fs::read_to_string(&rules_path).unwrap_or_default();

    let key = if key_path.exists() {
        let hex = fs::read_to_string(&key_path)
            .map_err(|e| format!("Failed to read policy key: {}", e))?;
        crate::crypto::hex_to_bytes(hex.trim())
            .ok_or("Policy key file is corrupted (invalid hex)")?
    } else {
        let key = generate_random_key()?;
        let hex = crate::crypto::bytes_to_hex(&key);
        // Write with 0o600 from creation to close the TOCTOU window where
        // fs::write + chmod would briefly expose the key to other local users.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(|e| format!("Failed to write policy key: {}", e))?;
            f.write_all(hex.as_bytes())
                .map_err(|e| format!("Failed to write policy key data: {}", e))?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&key_path, &hex).map_err(|e| format!("Failed to write policy key: {}", e))?;
        }
        key
    };

    let sig = crate::crypto::hmac_sign(&key, rules_content.as_bytes());
    let sig_path = config_dir.join("policy.sig");
    fs::write(&sig_path, &sig).map_err(|e| format!("Failed to write policy.sig: {}", e))?;
    // policy.sig is HMAC output — keep it owner-only (matching .key)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&sig_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!(
                "kiteguard: WARNING — could not restrict {} permissions: {}. \
Manually run: chmod 600 {}",
                sig_path.display(),
                e,
                sig_path.display()
            );
        }
    }

    // Write sentinel so verify_policy_signature() can detect if key files are
    // later deleted to bypass signature enforcement.
    let sentinel_path = config_dir.join(".signature_required");
    if !sentinel_path.exists() {
        fs::write(&sentinel_path, "1")
            .map_err(|e| format!("Failed to write .signature_required sentinel: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&sentinel_path, std::fs::Permissions::from_mode(0o600))
            {
                eprintln!(
                    "kiteguard: WARNING — could not restrict {} permissions: {}. \
Manually run: chmod 600 {}",
                    sentinel_path.display(),
                    e,
                    sentinel_path.display()
                );
            }
        }
    }

    // Write a key fingerprint (SHA-256 of the raw key bytes) as a second
    // independent sentinel.  Unlike .signature_required it contains no key
    // material so there is no legitimate reason to delete it.  Both sentinels
    // must be absent before we treat the install as "not yet signed".
    let fingerprint = crate::crypto::sha256_hex(&key);
    let fingerprint_path = config_dir.join(".key_fingerprint");
    fs::write(&fingerprint_path, &fingerprint)
        .map_err(|e| format!("Failed to write .key_fingerprint: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&fingerprint_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!(
                "kiteguard: WARNING — could not restrict {} permissions: {}. \
Manually run: chmod 600 {}",
                fingerprint_path.display(),
                e,
                fingerprint_path.display()
            );
        }
    }

    Ok(())
}

fn generate_random_key() -> Result<Vec<u8>> {
    use std::io::Read;
    let mut key = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .map_err(|e| format!("Failed to generate key from /dev/urandom: {}", e))?;
    Ok(key)
}

fn current_binary_path() -> Result<String> {
    std::env::current_exe()
        .map_err(|e| format!("Could not determine kiteguard binary path: {}", e))?
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Binary path is not valid UTF-8".into())
}

/// kiteguard init --cursor — registers hooks for Cursor.
///
/// Writes two hook files in Cursor's `hooks.json` format:
///   1. .cursor/hooks.json  (project-level, commit to repo)
///   2. ~/.cursor/hooks.json  (user-level, active for all workspaces)
///
/// Security hooks use `failClosed: true` so that kiteguard crashes or
/// timeouts block the action rather than silently allowing it through.
///
/// Event mapping:
///   beforeSubmitPrompt   → prompt injection / PII scan
///   preToolUse           → dangerous command / path / secret detection
///   beforeShellExecution → shell command scan (different payload schema)
///   beforeReadFile       → path + file content scan before AI sees it
///   postToolUse          → post-tool response inspection
///   afterShellExecution  → bash output scan
///   beforeMCPExecution   → MCP server URL + command + tool_input scan
///   afterMCPExecution    → MCP result scan for secrets/PII
///   beforeTabFileRead    → path + content scan for Tab completions
///   afterAgentResponse   → final response scan for secrets/PII
pub fn run_cursor() -> Result<()> {
    let binary_path = current_binary_path()?;

    // Ask the user where to install
    println!("Where should kiteguard hooks be installed?");
    println!();
    println!("  1) Project only  — .cursor/hooks.json in current directory (commit to repo)");
    println!("  2) User only     — ~/.cursor/hooks.json (active in all Cursor workspaces)");
    println!("  3) Both          — project + user level (recommended)");
    println!();
    print!("Enter choice [1/2/3] (default: 3): ");
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;
    let choice = input.trim();

    let install_project = matches!(choice, "" | "1" | "3");
    let install_user = matches!(choice, "" | "2" | "3");

    if !install_project && !install_user {
        return Err(format!("Invalid choice '{}'. Please enter 1, 2, or 3.", choice).into());
    }

    let hook_config = serde_json::json!({
        "version": 1,
        "hooks": {
            // Pre-execution (blocking) — failClosed so crashes block rather than allow
            "beforeSubmitPrompt":   [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            "preToolUse":           [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            "beforeShellExecution": [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            "beforeReadFile":       [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            "beforeMCPExecution":   [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            "beforeTabFileRead":    [{ "command": binary_path, "timeout": 30, "failClosed": true }],
            // Post-execution (auditing) — fail-open so crashes don't interrupt workflow
            "postToolUse":          [{ "command": binary_path, "timeout": 30 }],
            "afterShellExecution":  [{ "command": binary_path, "timeout": 30 }],
            "afterMCPExecution":    [{ "command": binary_path, "timeout": 30 }],
            "afterAgentResponse":   [{ "command": binary_path, "timeout": 30 }]
        }
    });
    let hook_json = serde_json::to_string_pretty(&hook_config)?;

    let mut project_path_opt: Option<std::path::PathBuf> = None;
    let mut user_path_opt: Option<std::path::PathBuf> = None;

    // Project-level: .cursor/hooks.json
    if install_project {
        let project_dir = std::path::PathBuf::from(".cursor");
        fs::create_dir_all(&project_dir)
            .map_err(|e| format!("Could not create .cursor/: {}", e))?;
        let project_path = project_dir.join("hooks.json");
        fs::write(&project_path, &hook_json)
            .map_err(|e| format!("Could not write {}: {}", project_path.display(), e))?;
        project_path_opt = Some(project_path);
    }

    // User-level: ~/.cursor/hooks.json
    if install_user {
        let user_dir = crate::util::home_dir().join(".cursor");
        fs::create_dir_all(&user_dir).map_err(|e| format!("Could not create ~/.cursor/: {}", e))?;
        let user_path = user_dir.join("hooks.json");
        fs::write(&user_path, &hook_json)
            .map_err(|e| format!("Could not write {}: {}", user_path.display(), e))?;
        user_path_opt = Some(user_path);
    }

    // Shared config dir + policy signing
    let config_dir = crate::util::home_dir().join(".kiteguard");
    fs::create_dir_all(&config_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700));
    }
    sign_policy(&config_dir)?;

    println!();
    println!("kiteguard initialized for Cursor!");
    println!();
    if let Some(p) = project_path_opt {
        println!(
            "  Project hooks: {}",
            p.canonicalize().unwrap_or(p).display()
        );
    }
    if let Some(u) = user_path_opt {
        println!("  User hooks:    {}", u.display());
    }
    println!("  Config dir:    {}", config_dir.display());
    println!(
        "  Audit log:     {}",
        config_dir.join("audit.log").display()
    );
    println!();
    println!("Next steps:");
    if install_project {
        println!("  1. Commit .cursor/hooks.json to your repo");
    }
    println!(
        "  {}. Reload Cursor — hooks load automatically on save",
        if install_project { 2 } else { 1 }
    );
    println!(
        "  {}. Open Cursor agent mode — every tool call is now guarded",
        if install_project { 3 } else { 2 }
    );
    println!();
    println!("Debug: Cursor Settings → Hooks tab, or View → Output → 'Cursor Hooks'");

    Ok(())
}

/// kiteguard init --gemini — registers hooks for Gemini CLI.
///
/// Gemini CLI uses a nested hook format with matchers and millisecond timeouts.
/// Writes two settings files:
///   1. .gemini/settings.json  (project-level, commit to repo)
///   2. ~/.gemini/settings.json  (user-level, always active)
///
/// Event mapping:
///   BeforeAgent  → prompt injection / PII scan
///   BeforeTool   → dangerous command / path / secret detection
///   AfterTool    → post-tool response inspection
///   AfterAgent   → session-end logging
pub fn run_gemini(verbose: bool) -> Result<()> {
    let binary_path = current_binary_path()?;

    // When verbose mode is requested, wrap the command so that
    // KITEGUARD_VERBOSE=1 is set for every hook invocation.
    let cmd = if verbose {
        format!("env KITEGUARD_VERBOSE=1 {}", binary_path)
    } else {
        binary_path.clone()
    };

    // Gemini's nested hook format: each event maps to [{matcher, hooks: [...]}]
    let make_hooks = |bp: &str| {
        serde_json::json!([{
            "matcher": "*",
            "hooks": [{
                "name": "kiteguard",
                "type": "command",
                "command": bp,
                "timeout": 30000,
                "description": "Runtime security guardrails: blocks dangerous commands, secrets, PII, and prompt injection"
            }]
        }])
    };

    let hook_config = serde_json::json!({
        "hooks": {
            "BeforeAgent": make_hooks(&cmd),
            "BeforeTool":  make_hooks(&cmd),
            "AfterTool":   make_hooks(&cmd),
            "AfterAgent":  make_hooks(&cmd)
        }
    });
    let hook_json = serde_json::to_string_pretty(&hook_config)?;

    // 1. Project-level: .gemini/settings.json (relative to cwd)
    let project_dir = std::path::PathBuf::from(".gemini");
    fs::create_dir_all(&project_dir).map_err(|e| format!("Could not create .gemini/: {}", e))?;
    let project_path = project_dir.join("settings.json");
    fs::write(&project_path, &hook_json)
        .map_err(|e| format!("Could not write {}: {}", project_path.display(), e))?;

    // 2. User-level: ~/.gemini/settings.json (active for all projects)
    let user_dir = crate::util::home_dir().join(".gemini");
    fs::create_dir_all(&user_dir).map_err(|e| format!("Could not create ~/.gemini/: {}", e))?;
    let user_path = user_dir.join("settings.json");
    fs::write(&user_path, &hook_json)
        .map_err(|e| format!("Could not write {}: {}", user_path.display(), e))?;

    // Shared config dir + policy signing
    let config_dir = crate::util::home_dir().join(".kiteguard");
    fs::create_dir_all(&config_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700));
    }
    sign_policy(&config_dir)?;

    println!("kiteguard initialized for Gemini CLI!");
    if verbose {
        println!("  Verbose mode: ON (KITEGUARD_VERBOSE=1 baked into hooks)");
    }
    println!();
    println!(
        "  Project hooks: {}",
        project_path
            .canonicalize()
            .unwrap_or(project_path)
            .display()
    );
    println!("  User hooks:    {}", user_path.display());
    println!("  Config dir:    {}", config_dir.display());
    println!(
        "  Audit log:     {}",
        config_dir.join("audit.log").display()
    );
    println!();
    println!("Next steps:");
    println!("  1. Commit .gemini/settings.json to your repo");
    println!("  2. Start a Gemini CLI session — every tool call is now guarded");
    println!();
    println!("Verify with: kiteguard audit");

    Ok(())
}
