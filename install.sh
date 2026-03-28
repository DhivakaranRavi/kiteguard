#!/usr/bin/env bash
set -euo pipefail

REPO="DhivakaranRavi/kiteguard"
INSTALL_DIR="/usr/local/bin"
BINARY="kiteguard"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  TARGET_OS="linux" ;;
  Darwin) TARGET_OS="macos" ;;
  *)
    echo "Unsupported OS: $OS"
    echo "Please build from source: https://github.com/$REPO"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)           TARGET_ARCH="x86_64" ;;
  arm64 | aarch64)  TARGET_ARCH="aarch64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Please build from source: https://github.com/$REPO"
    exit 1
    ;;
esac

echo "Installing kiteguard..."
echo "  OS:   $TARGET_OS"
echo "  Arch: $TARGET_ARCH"

# Fetch the latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo ""
  echo "No release found yet. Building from source instead..."
  echo ""

  if ! command -v cargo &>/dev/null; then
    echo "Rust/cargo not found. Install Rust first: https://rustup.rs"
    exit 1
  fi

  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT

  git clone --depth 1 "https://github.com/$REPO.git" "$TMP/kiteguard"
  cargo build --release --manifest-path "$TMP/kiteguard/Cargo.toml"
  BUILT="$TMP/kiteguard/target/release/$BINARY"
else
  ASSET="${BINARY}-${TARGET_ARCH}-${TARGET_OS}.tar.gz"
  URL="https://github.com/$REPO/releases/download/$LATEST/$ASSET"

  echo "  Version: $LATEST"
  echo "  Downloading: $URL"
  echo ""

  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT

  curl -fsSL "$URL" -o "$TMP/$ASSET"
  tar -xzf "$TMP/$ASSET" -C "$TMP"
  BUILT="$TMP/$BINARY"
fi

# Install binary
if [ -w "$INSTALL_DIR" ]; then
  install -m 755 "$BUILT" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo install -m 755 "$BUILT" "$INSTALL_DIR/$BINARY"
fi

echo "kiteguard installed to $INSTALL_DIR/$BINARY"
echo ""
echo "Next: run 'kiteguard init' to register hooks with Claude Code."
