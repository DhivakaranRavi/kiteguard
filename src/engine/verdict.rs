#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Verdict {
    Allow,
    Block {
        rule: String,
        reason: String,
    },
    /// Not provably unsafe, but irreversible or externally visible: a human must approve.
    Confirm {
        rule: String,
        reason: String,
    },
    Redact {
        original: String,
        redacted: String,
    },
}

impl Verdict {
    pub fn block(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Verdict::Block {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    pub fn confirm(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Verdict::Confirm {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    #[allow(dead_code)]
    pub fn is_confirm(&self) -> bool {
        matches!(self, Verdict::Confirm { .. })
    }

    /// Block > Confirm > everything else; used to pick the strongest of several verdicts.
    pub fn severity(&self) -> u8 {
        match self {
            Verdict::Block { .. } => 2,
            Verdict::Confirm { .. } => 1,
            _ => 0,
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
            Verdict::Confirm { .. } => "confirm",
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
    fn confirm_ranks_between_allow_and_block() {
        let c = Verdict::confirm("r", "why");
        assert!(c.is_confirm() && !c.is_block() && !c.is_allow());
        assert_eq!(c.as_str(), "confirm");
        assert!(Verdict::block("r", "w").severity() > c.severity());
        assert!(c.severity() > Verdict::Allow.severity());
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
