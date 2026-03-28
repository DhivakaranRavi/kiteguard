#!/usr/bin/env bash
set -euo pipefail

# kiteguard uninstaller
# Usage: curl -sSL https://raw.githubusercontent.com/DhivakaranRavi/kiteguard/main/scripts/uninstall.sh | bash

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="kiteguard"
CLAUDE_SETTINGS="${HOME}/.claude/settings.json"
CONFIG_DIR="${HOME}/.kiteguard"

echo "Uninstalling kiteguard..."

# ── Remove hooks from Claude Code settings ────────────────────────────────────
if [[ -f "${CLAUDE_SETTINGS}" ]]; then
    if command -v python3 &>/dev/null; then
        python3 - <<EOF
import json
path = "${CLAUDE_SETTINGS}"
with open(path) as f:
    data = json.load(f)
data.pop("hooks", None)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
print("  Hooks removed from ~/.claude/settings.json")
EOF
    else
        echo "  Warning: python3 not found — please manually remove the 'hooks' key from ${CLAUDE_SETTINGS}"
    fi
else
    echo "  No ~/.claude/settings.json found, skipping hook removal."
fi

# ── Remove binary ─────────────────────────────────────────────────────────────
if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    if [[ -w "${INSTALL_DIR}" ]]; then
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    echo "  Removed ${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "  Binary not found at ${INSTALL_DIR}/${BINARY_NAME}, skipping."
fi

echo ""
echo "kiteguard uninstalled. Claude Code sessions are no longer guarded."
echo ""
echo "  Audit log and config preserved at ${CONFIG_DIR}"
echo "  To also remove logs: rm -rf ${CONFIG_DIR}"
