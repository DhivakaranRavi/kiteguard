# Installation

## Requirements

- macOS or Linux
- [Claude Code](https://claude.ai/code) installed

## One-line install

```bash
curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/install.sh | bash
```

This:
1. Detects your OS and architecture
2. Downloads the correct pre-built binary
3. Verifies the checksum
4. Installs to `/usr/local/bin/kiteguard`
5. Runs `kiteguard init` to register hooks with Claude Code

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
kiteguard init
```

## Build from source

```bash
git clone https://github.com/DhivakaranRavi/kiteguard
cd kiteguard
cargo build --release
./target/release/kiteguard init
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
