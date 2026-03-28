# Contributing to kiteguard

Thank you for helping make AI coding agents safer.

## Quick start

```bash
git clone https://github.com/DhivakaranRavi/kiteguard
cd kiteguard
cargo build
cargo test
```

## How to add a new detector

1. Add patterns to the relevant file in `src/detectors/`
2. Add a test in `tests/detectors/`
3. Run `cargo test` to verify
4. Update `CHANGELOG.md`

## How to add a new policy option

1. Add the field to the relevant struct in `src/engine/policy.rs`
2. Wire it into `src/engine/evaluator.rs`
3. Add a default value
4. Document it in `docs/configuration.md`

## Pull request checklist

- [ ] `cargo fmt` applied
- [ ] `cargo clippy` — zero warnings
- [ ] Tests added for new behavior
- [ ] `CHANGELOG.md` updated

## Reporting security vulnerabilities

Do **not** open a public GitHub issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the private disclosure process.

## Code of conduct

Be respectful. Focus on the code, not the person.
