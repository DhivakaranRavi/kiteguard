/// Labeled evaluation: runs eval/dataset.jsonl through the default policy and reports
/// recall (malicious blocked), false-positive rate (benign blocked) and precision,
/// per category and per split, with 95% Wilson intervals.
///
///   cargo test --test eval_tests -- --nocapture
///
/// Tune detectors against `dev` only. `test` is reported in aggregate; its individual
/// misses are hidden unless EVAL_SHOW_TEST=1, so it stays a fair out-of-sample number.
/// EVAL_SHOW_DEV=0 hides the dev miss listing.
use kiteguard::engine::{evaluator, policy::Policy};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Default, Clone, Copy)]
struct Tally {
    tp: u32,  // malicious, blocked
    fn_: u32, // malicious, allowed
    fp: u32,  // benign, blocked
    tn: u32,  // benign, allowed
}

impl Tally {
    fn add(&mut self, malicious: bool, blocked: bool) {
        match (malicious, blocked) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }
    fn mal(&self) -> u32 {
        self.tp + self.fn_
    }
    fn ben(&self) -> u32 {
        self.fp + self.tn
    }
}

fn wilson(k: u32, n: u32) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    let (k, n) = (k as f64, n as f64);
    let z = 1.96_f64;
    let p = k / n;
    let d = 1.0 + z * z / n;
    let c = p + z * z / (2.0 * n);
    let m = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt();
    ((c - m) / d, (c + m) / d)
}

fn pct(x: f64) -> String {
    format!("{:5.1}%", x * 100.0)
}

fn fmt_rate(k: u32, n: u32) -> String {
    if n == 0 {
        return "   n/a".into();
    }
    let (lo, hi) = wilson(k, n);
    format!(
        "{} [{:.0}-{:.0}] {:>3}/{:<3}",
        pct(k as f64 / n as f64),
        lo * 100.0,
        hi * 100.0,
        k,
        n
    )
}

/// 0 = allowed, 1 = asks a human, 2 = blocked.
fn severity(kind: &str, input: &str, pol: &Policy) -> u8 {
    let v = match kind {
        "command" => evaluator::evaluate_command(input, pol),
        "url" => evaluator::evaluate_url(input, pol),
        "read_path" => evaluator::evaluate_file_read(input, pol),
        "write_path" => evaluator::evaluate_file_write(input, pol),
        "content" => evaluator::evaluate_file_content(input, pol),
        other => panic!("unknown kind {other}"),
    };
    v.severity()
}

fn summary(title: &str, t: &Tally) {
    let prec_n = t.tp + t.fp;
    println!(
        "  {:<10} recall {}   FPR {}   precision {}",
        title,
        fmt_rate(t.tp, t.mal()),
        fmt_rate(t.fp, t.ben()),
        if prec_n == 0 {
            "n/a".to_string()
        } else {
            pct(t.tp as f64 / prec_n as f64)
        }
    );
}

#[test]
fn eval_report() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/eval/dataset.jsonl");
    let Ok(raw) = std::fs::read_to_string(path) else {
        eprintln!("eval/dataset.jsonl not found; run `python3 eval/generate.py` first. Skipping.");
        return;
    };
    let pol = Policy::default();
    let show_test = std::env::var("EVAL_SHOW_TEST").is_ok_and(|v| v == "1");
    let show_dev = std::env::var("EVAL_SHOW_DEV").map_or(true, |v| v != "0");

    let mut overall: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_cat: BTreeMap<(String, String), Tally> = BTreeMap::new();
    let mut misses: Vec<(String, String, String, String, String)> = vec![];
    let mut n = 0;
    let mut asked_benign: BTreeMap<String, u32> = BTreeMap::new();
    let mut hard: BTreeMap<String, Tally> = BTreeMap::new(); // block-only view

    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let r: Value = serde_json::from_str(line).expect("bad jsonl line");
        let (kind, input) = (r["kind"].as_str().unwrap(), r["input"].as_str().unwrap());
        let (label, cat, split) = (
            r["label"].as_str().unwrap(),
            r["category"].as_str().unwrap(),
            r["split"].as_str().unwrap(),
        );
        let malicious = label == "malicious";
        let sev = severity(kind, input, &pol);
        let b = sev > 0;
        n += 1;
        hard.entry(split.into())
            .or_default()
            .add(malicious, sev == 2);
        if !malicious && sev == 1 {
            *asked_benign.entry(split.into()).or_default() += 1;
        }
        overall.entry(split.into()).or_default().add(malicious, b);
        overall.entry("all".into()).or_default().add(malicious, b);
        by_cat
            .entry((split.into(), cat.into()))
            .or_default()
            .add(malicious, b);
        let friction = !malicious && sev == 1;
        if malicious != b || friction {
            let what = if malicious {
                "MISSED"
            } else if friction {
                "BENIGN-ASKED"
            } else {
                "FALSE-POSITIVE"
            };
            misses.push((
                split.into(),
                what.into(),
                cat.into(),
                kind.into(),
                input.into(),
            ));
        }
    }
    assert!(n >= 500, "dataset suspiciously small: {n}");

    println!("\n=== kiteguard eval: {n} labeled examples, default policy ===");
    println!("rates are x% [95% Wilson CI] k/n\n");
    for s in ["dev", "test", "independent", "all"] {
        if let Some(t) = overall.get(s) {
            summary(s, t);
        }
    }

    println!("\n(caught = blocked OR asks a human; FPR counts benign blocked or asked)");
    for s in ["dev", "test", "independent"] {
        if let Some(t) = hard.get(s) {
            println!("  {:<10} block-only recall {}", s, fmt_rate(t.tp, t.mal()));
        }
        println!(
            "  {:<10} benign that only ask (friction, included in FPR): {}",
            s,
            asked_benign.get(s).copied().unwrap_or(0)
        );
    }

    for split in ["dev", "test", "independent"] {
        println!("\n--- per category ({split}) ---");
        for ((s, cat), t) in &by_cat {
            if s != split {
                continue;
            }
            if t.mal() > 0 {
                println!("  {:<18} recall {}", cat, fmt_rate(t.tp, t.mal()));
            } else {
                println!("  {:<18} FPR    {}", cat, fmt_rate(t.fp, t.ben()));
            }
        }
    }

    println!("\n--- failures ---");
    for (split, what, cat, kind, input) in &misses {
        let visible = (split == "dev" && show_dev)
            || ((split == "test" || split == "independent") && show_test);
        if visible {
            let one_line: String = input.replace('\n', "\\n").chars().take(110).collect();
            println!("  [{split}] {what:<14} {cat:<18} {kind:<10} {one_line}");
        }
    }
    let hidden = misses
        .iter()
        .filter(|m| m.0 == "test" && !show_test)
        .count();
    if hidden > 0 {
        println!("  ({hidden} test-split failures hidden; set EVAL_SHOW_TEST=1 to list)");
    }
}
