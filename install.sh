#!/usr/bin/env bash
# Installs the Mobile App Tracking Debugger so mitmproxy / mitmweb / mitmdump load it automatically.
set -euo pipefail

# GitHub repository (used when the script is run via curl | bash).
# Always downloads the latest published release, never unreleased work.
REPO="michalnovacek96/mitmproxy"
RAW_URL="https://github.com/$REPO/releases/latest/download/app_tracking_debugger.py"

DIR="$HOME/.mitmproxy"
DEST="$DIR/addons/app_tracking_debugger.py"
CONFIG="$DIR/config.yaml"

mkdir -p "$DIR/addons"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/app_tracking_debugger.py"
if [ -f "$SRC" ]; then
  cp "$SRC" "$DEST"
  echo "Copied addon to $DEST"
else
  curl -fsSL "$RAW_URL" -o "$DEST"
  echo "Downloaded addon to $DEST"
fi

if [ -f "$CONFIG" ] && grep -q "app_tracking_debugger.py" "$CONFIG"; then
  echo "Already registered in $CONFIG"
elif [ -f "$CONFIG" ] && grep -q "^scripts:" "$CONFIG"; then
  echo
  echo "Your $CONFIG already has a 'scripts:' section."
  echo "Add this line under it manually:"
  echo "  - $DEST"
  exit 0
else
  printf '\nscripts:\n  - %s\n' "$DEST" >> "$CONFIG"
  echo "Registered in $CONFIG"
fi

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$DEST")
echo
echo "Done. Installed version ${VERSION:-unknown}."
echo "Start mitmweb - the tracking hits UI opens at http://127.0.0.1:8082"
