#!/usr/bin/env bash
set -euo pipefail

# kiteguard installer
# Usage: curl -sSL https://kiteguard.dev/install.sh | bash

REPO="DhivakaranRavi/kiteguard"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="kiteguard"
CONFIG_DIR="${HOME}/.kiteguard"

# ── Detect OS and architecture ────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${ARCH}" in
    x86_64)  ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

case "${OS}" in
    linux)  PLATFORM="linux-${ARCH}" ;;
    darwin) PLATFORM="macos-${ARCH}" ;;
    *) echo "Unsupported OS: ${OS}"; exit 1 ;;
esac

# ── Get latest version ────────────────────────────────────────────────────────
echo "Fetching latest kiteguard release..."
VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/')

if [[ -z "${VERSION}" ]]; then
    echo "Could not determine latest version. Check https://github.com/${REPO}/releases"
    exit 1
fi

echo "Installing kiteguard ${VERSION} for ${PLATFORM}..."

# ── Download binary ───────────────────────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${PLATFORM}"
TMP_FILE=$(mktemp)

curl -sSfL "${DOWNLOAD_URL}" -o "${TMP_FILE}"
chmod +x "${TMP_FILE}"

# ── Verify checksum ───────────────────────────────────────────────────────────
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.sha256"
EXPECTED=$(curl -sSfL "${CHECKSUM_URL}" | grep "${BINARY_NAME}-${PLATFORM}" | awk '{print $1}')

if [[ -n "${EXPECTED}" ]]; then
    ACTUAL=$(sha256sum "${TMP_FILE}" 2>/dev/null || shasum -a 256 "${TMP_FILE}" | awk '{print $1}')
    if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
        echo "Checksum verification FAILED. Aborting installation."
        rm -f "${TMP_FILE}"
        exit 1
    fi
    echo "Checksum verified ✓"
fi

# ── Install binary ────────────────────────────────────────────────────────────
if [[ -w "${INSTALL_DIR}" ]]; then
    mv "${TMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo mv "${TMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"

# ── Create config directory ───────────────────────────────────────────────────
mkdir -p "${CONFIG_DIR}"

# ── Register hooks with Claude Code ──────────────────────────────────────────
"${INSTALL_DIR}/${BINARY_NAME}" init

echo ""
echo "kiteguard is active. Every Claude Code session is now guarded."
echo ""
echo "Commands:"
echo "  kiteguard audit    — view blocked/allowed events"
echo "  kiteguard policy   — view active security policies"
echo "  kiteguard --help   — show all commands"
