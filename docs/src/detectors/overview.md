# Detectors Overview

kiteguard ships six built-in detectors. Each detector is a pure Rust function that takes a string input and returns a `Verdict`.

## Detector inventory

| Detector   | Triggered by                    | Configurable? |
|------------|---------------------------------|---------------|
| `commands` | Bash tool commands              | Yes — `bash.block_patterns` |
| `paths`    | Read/Write/Edit file paths      | Yes — `file_paths.block_read/write` |
| `pii`      | Prompts, file content, responses| Partially — types list + enable flags |
| `secrets`  | File content, responses         | No — hardcoded patterns |
| `injection`| All text inputs                 | No — hardcoded patterns (toggle only) |
| `urls`     | WebFetch/WebSearch URLs         | Yes — `urls.block_domains` |

## Execution model

Each detector receives the full input string and returns either `Verdict::Allow` or `Verdict::Block { rule, reason }`. The evaluator layer is responsible for routing tool inputs to the right detector(s).

Multiple detectors can run on a single input. The first `Block` verdict wins and short-circuits evaluation.

## Performance

All detectors use compiled `Regex` objects cached at startup. Pattern compilation happens once per binary invocation. Typical evaluation time per input: **< 1 ms**.

No detector makes network calls (webhook dispatch happens after evaluation in `main.rs`).

## Source locations

| Detector   | Source file                        |
|------------|------------------------------------|
| `commands` | `src/detectors/commands.rs`        |
| `paths`    | `src/detectors/paths.rs`           |
| `pii`      | `src/detectors/pii.rs`             |
| `secrets`  | `src/detectors/secrets.rs`         |
| `injection`| `src/detectors/injection.rs`       |
| `urls`     | `src/detectors/urls.rs`            |
