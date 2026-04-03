use crate::engine::policy;
use crate::error::Result;

/// `kiteguard explain` — print a human-readable description of every active
/// policy rule so developers understand exactly what is being protected and why.
///
/// Usage:
///   kiteguard explain              # explain all rules
///   kiteguard explain bash         # explain bash block patterns only
///   kiteguard explain paths        # explain path rules
///   kiteguard explain pii          # explain PII types
///   kiteguard explain urls         # explain URL blocklist
///   kiteguard explain injection    # explain injection detection
pub fn run(args: &[String]) -> Result<()> {
    let section = args.first().map(|s| s.as_str()).unwrap_or("all");
    let p = policy::load()?;

    let show_all = section == "all";

    if show_all {
        println!("kiteguard — Active Policy Explanation");
        println!("======================================");
        if let Some(ref ver) = p.version {
            println!("Policy version: {}", ver);
        }
        if let Some(ref url) = p.remote_policy_url {
            println!("Remote policy URL: {}", url);
        }
        println!();
    }

    // ── Bash ─────────────────────────────────────────────────────────────────
    if show_all || section == "bash" {
        println!("[bash] Command execution protection");
        println!(
            "  Status: {}",
            if p.bash.enabled {
                "ENABLED"
            } else {
                "DISABLED"
            }
        );
        println!("  Fail-closed: {}", p.bash.block_on_error);
        println!();
        println!("  Block patterns ({}):", p.bash.block_patterns.len());
        for pat in &p.bash.block_patterns {
            println!("    - {}  →  {}", pat, explain_bash_pattern(pat));
        }
        if !p.bash.allow_patterns.is_empty() {
            println!();
            println!(
                "  Allow patterns (override blocks) ({}):",
                p.bash.allow_patterns.len()
            );
            for pat in &p.bash.allow_patterns {
                println!("    + {}", pat);
            }
        }
        println!();
    }

    // ── File paths ───────────────────────────────────────────────────────────
    if show_all || section == "paths" {
        println!("[paths] File path protection");
        println!();
        println!("  Blocked reads ({}):", p.file_paths.block_read.len());
        for pat in &p.file_paths.block_read {
            println!("    - {}", pat);
        }
        if !p.file_paths.allow_read.is_empty() {
            println!(
                "  Allowed reads (override blocks) ({}):",
                p.file_paths.allow_read.len()
            );
            for pat in &p.file_paths.allow_read {
                println!("    + {}", pat);
            }
        }
        println!();
        println!("  Blocked writes ({}):", p.file_paths.block_write.len());
        for pat in &p.file_paths.block_write {
            println!("    - {}", pat);
        }
        if !p.file_paths.allow_write.is_empty() {
            println!(
                "  Allowed writes (override blocks) ({}):",
                p.file_paths.allow_write.len()
            );
            for pat in &p.file_paths.allow_write {
                println!("    + {}", pat);
            }
        }
        println!();
    }

    // ── PII ──────────────────────────────────────────────────────────────────
    if show_all || section == "pii" {
        println!("[pii] Personally Identifiable Information detection");
        println!("  Block in prompts:       {}", p.pii.block_in_prompt);
        println!("  Block in file content:  {}", p.pii.block_in_file_content);
        println!("  Redact in responses:    {}", p.pii.redact_in_response);
        println!("  Active types ({}):", p.pii.types.len());
        for t in &p.pii.types {
            println!("    - {}  →  {}", t, explain_pii_type(t));
        }
        println!();
    }

    // ── URLs ─────────────────────────────────────────────────────────────────
    if show_all || section == "urls" {
        println!("[urls] URL / SSRF protection");
        println!("  Always blocked: cloud metadata endpoints, private IP ranges (SSRF)");
        println!("  Block list ({}):", p.urls.blocklist.len());
        for u in &p.urls.blocklist {
            println!("    - {}", u);
        }
        if !p.urls.allowlist.is_empty() {
            println!("  Allow list ({}):", p.urls.allowlist.len());
            for u in &p.urls.allowlist {
                println!("    + {}", u);
            }
        }
        println!();
    }

    // ── Injection ────────────────────────────────────────────────────────────
    if show_all || section == "injection" {
        println!("[injection] Prompt injection detection");
        println!(
            "  Status: {}",
            if p.injection.enabled {
                "ENABLED"
            } else {
                "DISABLED"
            }
        );
        println!("  Detects: ignore previous instructions, jailbreak attempts,");
        println!("           role-playing overrides, system prompt leaking commands.");
        println!();
    }

    // ── Webhook ──────────────────────────────────────────────────────────────
    if show_all {
        if let Some(ref wh) = p.webhook {
            println!("[webhook] Audit event forwarding");
            println!(
                "  Status:  {}",
                if wh.enabled { "ENABLED" } else { "DISABLED" }
            );
            println!("  URL:     {}", wh.url);
            println!(
                "  Token:   {}",
                if wh.token.is_some() {
                    "configured"
                } else {
                    "none"
                }
            );
            println!(
                "  HMAC:    {}",
                if wh.hmac_secret.is_some() {
                    "configured (X-KiteGuard-Signature header)"
                } else {
                    "not configured"
                }
            );
            println!();
        }
    }

    if section != "all" && !["bash", "paths", "pii", "urls", "injection"].contains(&section) {
        eprintln!("Unknown section: {}", section);
        eprintln!("Valid sections: bash, paths, pii, urls, injection");
        std::process::exit(1);
    }

    Ok(())
}

fn explain_bash_pattern(pat: &str) -> &'static str {
    if pat.contains("curl") || pat.contains("wget") {
        "Blocks download-and-execute pipe attacks"
    } else if pat.contains("rm") && pat.contains("rf") {
        "Blocks recursive force-delete of critical directories"
    } else if pat.contains("base64") {
        "Blocks base64-encoded payload execution (common obfuscation)"
    } else if pat.contains("/dev/tcp") {
        "Blocks bash TCP reverse shells"
    } else if pat.contains("nc") {
        "Blocks netcat reverse shell"
    } else if pat.contains("chmod") {
        "Blocks world-writable permission grants"
    } else if pat.contains("/etc/") {
        "Blocks writes to system config files"
    } else if pat.contains("crontab") {
        "Blocks cron persistence via crontab modification"
    } else if pat.contains("python") || pat.contains("perl") {
        "Blocks interpreter one-liner code execution"
    } else if pat.contains("mkfifo") {
        "Blocks named-pipe + netcat reverse shell"
    } else if pat.contains("bash -i") || pat.contains("sh -i") {
        "Blocks interactive reverse shell"
    } else if pat.contains("dd ") {
        "Blocks raw disk cloning"
    } else if pat.contains("fork bomb") || pat.contains(":(){ :|:") {
        "Blocks fork bomb resource exhaustion"
    } else {
        "Blocks dangerous shell command"
    }
}

fn explain_pii_type(t: &str) -> &'static str {
    match t {
        "ssn" => "US Social Security Number (XXX-XX-XXXX)",
        "credit_card" => "Payment card number (Luhn-validated)",
        "email" => "Email address",
        "phone" => "Phone number (various formats)",
        _ => "Custom PII type",
    }
}
