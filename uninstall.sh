#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
BINARY="kiteguard"
BINARY_PATH="$INSTALL_DIR/$BINARY"
SETTINGS="$HOME/.claude/settings.json"
CONFIG_DIR="$HOME/.kiteguard"

echo "Uninstalling kiteguard..."

# Remove hooks from ~/.claude/settings.json
if [ -f "$SETTINGS" ]; then
  if command -v python3 &>/dev/null; then
    python3 - <<'EOF'
import json, os
path = os.path.expanduser("~/.claude/settings.json")
with open(path) as f:
    data = json.load(f)
data.pop("hooks", None)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
print("  Hooks removed from ~/.claude/settings.json")
EOF
  else
    echo "  Warning: python3 not found — please manually remove the 'hooks' key from $SETTINGS"
  fi
else
  echo "  No ~/.claude/settings.json found, skipping hook removal."
fi

# Remove binary
if [ -f "$BINARY_PATH" ]; then
  if [ -w "$INSTALL_DIR" ]; then
    rm -f "$BINARY_PATH"
  else
    sudo rm -f "$BINARY_PATH"
  fi
  echo "  Removed $BINARY_PATH"
else
  echo "  Binary not found at $BINARY_PATH, skipping."
fi

echo ""
echo "kiteguard uninstalled."
echo "  Audit log and config preserved at $CONFIG_DIR"
echo "  To also remove logs: rm -rf $CONFIG_DIR"
