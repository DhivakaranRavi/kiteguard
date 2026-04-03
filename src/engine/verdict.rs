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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_is_allow() {
        assert!(Verdict::Allow.is_allow());
        assert!(!Verdict::Allow.is_block());
        assert_eq!(Verdict::Allow.as_str(), "allow");
    }

    #[test]
    fn block_is_block() {
        let v = Verdict::block("test_rule", "test reason");
        assert!(v.is_block());
        assert!(!v.is_allow());
        assert_eq!(v.as_str(), "block");
    }

    #[test]
    fn block_stores_rule_and_reason() {
        let v = Verdict::block("my_rule", "my reason");
        if let Verdict::Block { rule, reason } = v {
            assert_eq!(rule, "my_rule");
            assert_eq!(reason, "my reason");
        } else {
            panic!("expected Block variant");
        }
    }

    #[test]
    fn redact_as_str() {
        let v = Verdict::Redact {
            original: "a".into(),
            redacted: "b".into(),
        };
        assert_eq!(v.as_str(), "redact");
    }
}
