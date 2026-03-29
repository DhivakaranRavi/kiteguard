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

    let key =
        if key_path.exists() {
            let hex = fs::read_to_string(&key_path)
                .map_err(|e| format!("Failed to read policy key: {}", e))?;
            crate::crypto::hex_to_bytes(hex.trim())
                .ok_or("Policy key file is corrupted (invalid hex)")?
        } else {
            let key = generate_random_key()?;
            let hex = crate::crypto::bytes_to_hex(&key);
            fs::write(&key_path, &hex).map_err(|e| format!("Failed to write policy key: {}", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                {
                    eprintln!(
                    "kiteguard: WARNING — could not restrict signing key permissions ({}): {}. \
Policy signing may be weaker. Manually run: chmod 600 {}",
                    key_path.display(), e, key_path.display()
                );
                }
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
