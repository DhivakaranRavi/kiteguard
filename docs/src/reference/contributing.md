# Contributing

Thank you for helping improve kiteguard! This guide covers how to add new detectors, fix bugs, and submit pull requests.

## Getting started

```bash
git clone https://github.com/DhivakaranRavi/kiteguard
cd kiteguard
cargo build
cargo test
```

## Adding a new detector

1. Create `src/detectors/your_detector.rs`
2. Implement the function signature:

```rust
use crate::engine::{policy::Policy, verdict::Verdict};

pub fn scan(input: &str, policy: &Policy) -> Verdict {
    // ...
}
```

3. Add `pub mod your_detector;` to `src/detectors/mod.rs`
4. Wire it into the evaluator in `src/engine/evaluator.rs`
5. Add tests in the same file under `#[cfg(test)]`

## Adding a new pattern to an existing detector

For user-configurable detectors (`commands`, `paths`, `urls`): add the pattern to `config/rules.json` and document it.

For hardcoded detectors (`secrets`, `injection`): add the pattern string to the constant array in the source file, add a test case, and update the documentation page.

## Writing tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_evil_pattern() {
        let result = scan("evil input", &default_policy());
        assert!(matches!(result, Verdict::Block { .. }));
    }

    #[test]
    fn allows_clean_input() {
        let result = scan("normal text", &default_policy());
        assert_eq!(result, Verdict::Allow);
    }
}
```

Run with `cargo test`.

## Code standards

- Run `cargo fmt` before committing
- Fix all `cargo clippy` warnings
- Run `cargo audit` to check for vulnerable dependencies
- New public functions need doc comments (`///`)

## Pull request checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy` is clean
- [ ] `cargo fmt` applied
- [ ] New patterns include test cases for both match and non-match
- [ ] Documentation updated (add or update the relevant page in `docs/src/`)

## Reporting security issues

See [SECURITY.md](https://github.com/DhivakaranRavi/kiteguard/blob/main/SECURITY.md) — use GitHub Private Security Advisories, not a public issue.
