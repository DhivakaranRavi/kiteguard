#!/usr/bin/env bash
set -euo pipefail

# kiteguard uninstaller

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="kiteguard"
CLAUDE_SETTINGS="${HOME}/.claude/settings.json"

echo "Uninstalling kiteguard..."

# ── Remove hooks from Claude Code settings ────────────────────────────────────
if [[ -f "${CLAUDE_SETTINGS}" ]]; then
    # Remove hooks keys added by kiteguard using python (available on macOS/Linux)
    python3 - <<EOF
import json, sys
with open("${CLAUDE_SETTINGS}", "r") as f:
    settings = json.load(f)
settings.pop("hooks", None)
with open("${CLAUDE_SETTINGS}", "w") as f:
    json.dump(settings, f, indent=2)
print("Hooks removed from ~/.claude/settings.json")
EOF
fi

# ── Remove binary ─────────────────────────────────────────────────────────────
if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    if [[ -w "${INSTALL_DIR}" ]]; then
        rm "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo rm "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    echo "Binary removed from ${INSTALL_DIR}"
fi

echo ""
echo "kiteguard uninstalled. Claude Code sessions are no longer guarded."
echo ""
echo "Note: audit logs remain at ~/.kiteguard/audit.log"
echo "Remove manually with: rm -rf ~/.kiteguard"
