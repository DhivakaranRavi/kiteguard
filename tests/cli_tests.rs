/// Integration tests for new CLI subcommands added in v0.2.0:
/// `kiteguard test` and `kiteguard explain`.
///
/// These tests invoke the compiled binary via `assert_cmd` so they exercise
/// the full argument parsing → policy load → verdict path.
use assert_cmd::Command;

/// Returns a per-test temporary HOME directory so kiteguard uses built-in
/// default policy instead of whatever rules.json the CI runner may have.
/// Any stale rules.json from previous runs is removed so defaults always apply.
fn isolated_home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kiteguard-ci-{}", name));
    std::fs::create_dir_all(&dir).unwrap();
    // Remove any stale rules.json left by a previous test run so kiteguard
    // always falls back to built-in secure defaults in these tests.
    let _ = std::fs::remove_file(dir.join(".kiteguard").join("rules.json"));
    dir
}

// ─────────────────────────────────────────────
// kiteguard test
// ─────────────────────────────────────────────

#[test]
fn test_command_allow_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .env("HOME", isolated_home("allow"))
        .args(["test", "command", "ls -la"])
        .assert()
        .success();
}

#[test]
fn test_command_block_exits_two() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .env("HOME", isolated_home("block"))
        .args(["test", "command", "rm -rf /"])
        .assert()
        .code(2);
}

#[test]
fn test_url_ssrf_block_exits_two() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["test", "url", "http://169.254.169.254/latest/meta-data"])
        .assert()
        .code(2);
}

#[test]
fn test_url_safe_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["test", "url", "https://github.com"])
        .assert()
        .success();
}

#[test]
fn test_json_flag_allow_outputs_json() {
    let output = Command::cargo_bin("kiteguard")
        .unwrap()
        .env("HOME", isolated_home("json-allow"))
        .args(["test", "--json", "command", "ls -la"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(text.trim()).expect("output should be valid JSON");
    assert_eq!(parsed["verdict"], "allow");
    assert_eq!(parsed["type"], "command");
}

#[test]
fn test_json_flag_block_outputs_json_and_exits_two() {
    let output = Command::cargo_bin("kiteguard")
        .unwrap()
        .env("HOME", isolated_home("json-block"))
        .args(["test", "--json", "command", "rm -rf /"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(text.trim()).expect("output should be valid JSON");
    assert_eq!(parsed["verdict"], "block");
    assert!(
        parsed["rule"].is_string(),
        "block verdict should include rule"
    );
    assert!(
        parsed["reason"].is_string(),
        "block verdict should include reason"
    );
}

#[test]
fn test_missing_args_exits_one() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["test", "command"])
        .assert()
        .code(1);
}

#[test]
fn test_invalid_type_exits_one() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["test", "unknown_type", "some input"])
        .assert()
        .code(1);
}

// ─────────────────────────────────────────────
// kiteguard explain
// ─────────────────────────────────────────────

#[test]
fn explain_all_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain"])
        .assert()
        .success();
}

#[test]
fn explain_bash_section_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "bash"])
        .assert()
        .success();
}

#[test]
fn explain_paths_section_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "paths"])
        .assert()
        .success();
}

#[test]
fn explain_pii_section_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "pii"])
        .assert()
        .success();
}

#[test]
fn explain_urls_section_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "urls"])
        .assert()
        .success();
}

#[test]
fn explain_injection_section_exits_zero() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "injection"])
        .assert()
        .success();
}

#[test]
fn explain_invalid_section_exits_one() {
    Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain", "nonexistent"])
        .assert()
        .code(1);
}

#[test]
fn explain_all_output_contains_bash() {
    let output = Command::cargo_bin("kiteguard")
        .unwrap()
        .args(["explain"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).unwrap();
    assert!(
        text.contains("[bash]"),
        "explain output should include bash section"
    );
    assert!(
        text.contains("[pii]"),
        "explain output should include pii section"
    );
    assert!(
        text.contains("[urls]"),
        "explain output should include urls section"
    );
}
