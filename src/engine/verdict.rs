#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Verdict {
    Allow,
    Block { rule: String, reason: String },
    Redact { original: String, redacted: String },
}

impl Verdict {
    pub fn block(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Verdict::Block {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    #[allow(dead_code)]
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    #[allow(dead_code)]
    pub fn is_block(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Block { .. } => "block",
            Verdict::Redact { .. } => "redact",
        }
    }
}
