# Contributing to kiteguard

Thank you for helping make AI coding agents safer. All contributions are welcome — bug reports, documentation improvements, new detectors, and code fixes.

---

## Branch structure

```
main       ← stable releases only (tagged v0.1.0, v0.2.0...)
  └── develop  ← integration branch, always working
        ├── feat/your-feature
        └── fix/your-bugfix
```

- **`main`** — only receives merges from `develop` at release time. Never commit here directly.
- **`develop`** — the active development branch. All features and fixes merge here first.
- **`feat/*` / `fix/*`** — short-lived branches cut from `develop`, merged back via PR.

## How to contribute

kiteguard follows standard open-source contribution practices:

1. **Fork** the repository to your own GitHub account
2. **Create a branch from `develop`** — never work directly on `main` or `develop`
   ```bash
   git checkout develop
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/your-bug-description
   ```
3. **Make your changes** with tests
4. **Open a pull request against `develop`** — the maintainer will review and merge
5. **Releases** are made by merging `develop` → `main` and tagging a version

---

## Ground rules

- **All changes go through a pull request** — no exceptions
- Every PR must pass CI (`cargo fmt`, `cargo clippy -D warnings`, `cargo test --all`)
- Security-sensitive changes require extra review — tag `@DhivakaranRavi`
- Keep pull requests focused — one feature or fix per PR

---

## Development setup

```bash
git clone https://github.com/DhivakaranRavi/kiteguard
cd kiteguard
cargo build
cargo test --all
```

**Requirements:**
- Rust 1.75+ (`rustup update stable`)
- Node.js 22+ (for console UI only: `cd console && npm ci && npm run build`)

---

## Workflow

```
fork → branch from develop → PR → CI → merge to develop → release to main
```

1. **Fork** the repo on GitHub
2. **Create a branch** from `develop`:
   ```bash
   git checkout develop
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/your-bug-description
   ```
3. **Make your changes** with tests
4. **Run checks locally** before pushing:
   ```bash
   cargo fmt
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all
   ```
5. **Open a pull request against `develop`** — not `main`

---

## How to add a new detector

1. Add your logic to `src/detectors/<name>.rs`
2. Export it from `src/detectors/mod.rs`
3. Wire it into `src/engine/evaluator.rs`
4. Add at least 3 tests — one clean (allow), one malicious (block), one edge case
5. Document it in `docs/detectors/<name>.md`

## How to add a new policy option

1. Add the field to the struct in `src/engine/policy.rs`
2. Add a `default_*` function and wire it to `#[serde(default = "...")]`
3. Use it in `src/engine/evaluator.rs`
4. Add it to `config/rules.yaml` with a comment explaining the option
5. Document it in `docs/configuration/`

---

## Pull request checklist

- [ ] Branch is based on latest `main`
- [ ] `cargo fmt` applied (no diff)
- [ ] `cargo clippy --all-targets -- -D warnings` passes clean
- [ ] Tests added for new behaviour (aim for both allow + block cases)
- [ ] `cargo test --all` passes (190+ tests)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Docs updated if behaviour changed

---

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add GitLab token detector
fix: prevent glob cache unbounded growth
docs: update webhook configuration guide
test: add edge cases for IPv6 SSRF detection
refactor: simplify PII redaction logic
```

---

## Reporting security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Security issues are addressed with priority.

---

## Code of conduct

Be respectful. Focus on the code, not the person. Constructive feedback only.
