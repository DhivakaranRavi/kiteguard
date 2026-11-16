/// Mutation test: every malicious command in the eval set that kiteguard catches is rewritten
/// with common evasion wrappers. A mutant that is allowed is a bypass.
///
///   cargo test --test mutation_tests -- --nocapture
///   MUTATION_SHOW=1 ... lists surviving mutants
use kiteguard::engine::{evaluator, policy::Policy};
use serde_json::Value;
use std::collections::BTreeMap;

fn sq(s: &str) -> String {
    s.replace('\'', "'\\''")
}

fn split_first(cmd: &str) -> (&str, &str) {
    match cmd.split_once(' ') {
        Some((a, b)) => (a, b),
        None => (cmd, ""),
    }
}

fn mutants(cmd: &str) -> Vec<(&'static str, String)> {
    let (first, rest) = split_first(cmd);
    let mut v = vec![
        ("sudo", format!("sudo {cmd}")),
        ("bash -c", format!("bash -c '{}'", sq(cmd))),
        ("sh -c", format!("sh -c '{}'", sq(cmd))),
        ("env", format!("env FOO=1 {cmd}")),
        ("and-chain", format!("echo ok && {cmd}")),
        ("semicolon", format!("true; {cmd}")),
        ("newline", format!("true\n{cmd}")),
        ("stderr", format!("{cmd} 2>/dev/null")),
        ("background", format!("{cmd} &")),
        ("double-space", cmd.replace(' ', "  ")),
        ("tab", cmd.replace(' ', "\t")),
        ("subshell", format!("( {cmd} )")),
        ("command", format!("command {cmd}")),
        ("nohup", format!("nohup {cmd}")),
        ("time", format!("time {cmd}")),
        ("eval", format!("eval '{}'", sq(cmd))),
        ("brace-group", format!("{{ {cmd}; }}")),
        ("cd-prefix", format!("cd /tmp && {cmd}")),
    ];
    if first.chars().all(|c| c.is_ascii_alphabetic()) && first.len() > 2 {
        let (a, b) = first.split_at(first.len() / 2);
        v.push(("split-quote", format!("{a}''{b} {rest}")));
        v.push(("var-indirect", format!("P={first}; $P {rest}")));
        v.push(("abs-path", format!("/usr/bin/{first} {rest}")));
        v.push(("backslash", format!("\\{first} {rest}")));
    }
    v
}

#[test]
fn mutation_report() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/eval/dataset.jsonl");
    let Ok(raw) = std::fs::read_to_string(path) else {
        eprintln!("eval/dataset.jsonl not found; run `python3 eval/generate.py` first. Skipping.");
        return;
    };
    let pol = Policy::default();
    let show = std::env::var("MUTATION_SHOW").is_ok_and(|v| v == "1");

    let mut per: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let mut survivors: Vec<(String, String, String)> = vec![];
    let (mut total, mut survived) = (0u32, 0u32);

    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let r: Value = serde_json::from_str(line).unwrap();
        if r["kind"] != "command" || r["label"] != "malicious" {
            continue;
        }
        let cmd = r["input"].as_str().unwrap();
        if evaluator::evaluate_command(cmd, &pol).severity() == 0 {
            continue; // already a miss; not a mutation result
        }
        for (name, m) in mutants(cmd) {
            let e = per.entry(name).or_default();
            e.0 += 1;
            total += 1;
            if evaluator::evaluate_command(&m, &pol).severity() == 0 {
                e.1 += 1;
                survived += 1;
                survivors.push((name.into(), cmd.into(), m));
            }
        }
    }

    println!("\n=== mutation report: {total} mutants of caught commands ===");
    for (name, (n, s)) in &per {
        println!(
            "  {:<14} survived {:>4}/{:<5} ({:.1}%)",
            name,
            s,
            n,
            *s as f64 * 100.0 / *n as f64
        );
    }
    println!(
        "  TOTAL survival {survived}/{total} ({:.2}%)",
        survived as f64 * 100.0 / total as f64
    );
    if show {
        for (name, orig, m) in survivors.iter().take(60) {
            let one: String = m.replace('\n', "\\n").chars().take(120).collect();
            println!("  [{name}] {orig}  ->  {one}");
        }
    }
    assert!(
        (survived as f64) / (total as f64) < 0.02,
        "mutation survival regressed: {survived}/{total}"
    );
}
