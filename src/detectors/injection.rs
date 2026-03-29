use crate::engine::verdict::Verdict;
use regex::Regex;
use std::sync::OnceLock;

/// Known prompt injection patterns.
/// Detects attempts to override Claude's instructions via embedded text.
static INJECTION_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        "ignore_previous_instructions",
    ),
    (r"(?i)SYSTEM\s*:", "system_prefix_injection"),
    (r"(?i)you\s+are\s+now\s+(a\s+)?(?!claude)", "role_override"),
    (
        r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)",
        "disregard_instructions",
    ),
    (
        r"(?i)forget\s+(all\s+)?(previous|prior)\s+(instructions|context)",
        "forget_instructions",
    ),
    (
        r"(?i)IMPORTANT\s+UPDATE\s+FROM\s+(ANTHROPIC|CLAUDE|OPENAI)",
        "false_authority",
    ),
    (r"(?i)new\s+instructions?\s*:", "new_instructions_injection"),
    (
        r"(?i)\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>",
        "llm_token_injection",
    ),
    // Base64 encoded instruction attempts
    (r"(?i)eval\s*\(\s*atob\s*\(", "base64_eval_injection"),
    // Prompt leaking attempts
    (
        r"(?i)(repeat|print|output|reveal|show)\s+(your\s+)?(system\s+prompt|instructions|rules)",
        "prompt_leak",
    ),
];

static COMPILED: OnceLock<Vec<(Regex, String)>> = OnceLock::new();

fn compiled() -> &'static Vec<(Regex, String)> {
    COMPILED.get_or_init(|| {
        INJECTION_PATTERNS
            .iter()
            .map(|(pat, rule)| {
                (Regex::new(pat).expect("static injection pattern must compile"), rule.to_string())
            })
            .collect()
    })
}

/// Scans text for prompt injection patterns.
pub fn scan(text: &str) -> Option<Verdict> {
    for (re, rule) in compiled() {
        if re.is_match(text) {
            return Some(Verdict::block(
                rule.as_str(),
                format!("Prompt injection detected: {}", rule.replace('_', " ")),
            ));
        }
    }
    None
}
