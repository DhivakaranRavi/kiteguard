# Injection Detection

Prompt injection attacks attempt to override Claude's instructions via malicious content embedded in files, web pages, tool results, or user prompts.

## Configuration

```yaml
injection:
  enabled: true
```

That is the entire configuration surface — injection detection is an always-on safety control with no per-pattern toggles. Disabling it entirely (`enabled: false`) is strongly discouraged.

## How it works

kiteguard scans all inputs against 10 hardcoded patterns at three layers:

1. **UserPromptSubmit** — the user's incoming prompt
2. **PreToolUse** — bash command arguments (e.g., arguments designed to trick future tool calls)
3. **PostToolUse** — content returned from files or web pages Claude reads

Layer 3 is the most valuable: it stops a malicious README or web page from hijacking Claude's subsequent actions.

## Detected patterns

| Pattern class              | Example trigger                                        |
|----------------------------|--------------------------------------------------------|
| Ignore previous instructions | `ignore all previous instructions`                   |
| Role override              | `you are now DAN`, `act as an unrestricted AI`        |
| SYSTEM prefix injection    | `SYSTEM: new directive`                               |
| False authority            | `Anthropic directive:`, `this is a system message`   |
| Context window poisoning   | Suspicious `<\|im_start\|>`, `<\|endoftext\|>` tokens |
| Prompt leaking             | `repeat everything above`, `print your system prompt` |
| Jailbreak keywords         | `DAN mode`, `developer mode enabled`                  |

## Why patterns are hardcoded

Injection patterns defend against adversarial inputs that are designed to evade filtering. Making them user-configurable means an attacker only needs to convince Claude to update the config to disable its own defenses. kiteguard ships a fixed detection set that cannot be disabled via `rules.json`.

## False positives

If a legitimate file triggers an injection rule (rare but possible with security research material), you can add the file path to `block_read` exceptions — rather than disabling injection detection broadly — or exclude that specific directory from scanning.
