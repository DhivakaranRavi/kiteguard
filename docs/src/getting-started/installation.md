# Installation

## Requirements

- macOS or Linux
- At least one of: [Claude Code](https://claude.ai/code), [Cursor](https://cursor.com), or [Gemini CLI](https://github.com/google-gemini/gemini-cli)

## One-line install

```bash
curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/install.sh | bash
```

This:
1. Detects your OS and architecture
2. Downloads the correct pre-built binary
3. Verifies the checksum
4. Installs to `/usr/local/bin/kiteguard`
5. Runs `kiteguard init --claude-code` to register hooks with Claude Code

## Register with your agent

After the binary is installed, register hooks for whichever AI agent(s) you use:

```bash
# Claude Code
kiteguard init --claude-code

# Cursor  
kiteguard init --cursor

# Gemini CLI
kiteguard init --gemini
```

You can run multiple init commands to protect all agents simultaneously.

## Manual install

Download a binary from [GitHub Releases](https://github.com/DhivakaranRavi/kiteguard/releases):

| Platform | File |
|---|---|
| macOS Apple Silicon | `kiteguard-macos-arm64` |
| macOS Intel | `kiteguard-macos-x86_64` |
| Linux x86_64 | `kiteguard-linux-x86_64` |
| Linux ARM64 | `kiteguard-linux-arm64` |

```bash
# Example: macOS Apple Silicon
curl -sSfL https://github.com/DhivakaranRavi/kiteguard/releases/latest/download/kiteguard-macos-arm64 \
  -o /usr/local/bin/kiteguard
chmod +x /usr/local/bin/kiteguard
kiteguard init --claude-code   # or --cursor or --gemini
```

## Build from source

```bash
git clone https://github.com/DhivakaranRavi/kiteguard
cd kiteguard
cargo build --release
sudo install -m755 target/release/kiteguard /usr/local/bin/kiteguard
kiteguard init --claude-code
```

## Verify installation

```bash
kiteguard --version
kiteguard policy list
```

## Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/uninstall.sh | bash
```
