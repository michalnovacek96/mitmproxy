#!/usr/bin/env bash
# Installs the GA4 decoder so mitmproxy / mitmweb / mitmdump load it automatically.
set -euo pipefail

# GitHub repository (used when the script is run via curl | bash)
REPO="michalnovacek96/mitmproxy"
RAW_URL="https://raw.githubusercontent.com/$REPO/main/ga4_app_measurement.py"

DIR="$HOME/.mitmproxy"
DEST="$DIR/addons/ga4_app_measurement.py"
CONFIG="$DIR/config.yaml"

mkdir -p "$DIR/addons"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/ga4_app_measurement.py"
if [ -f "$SRC" ]; then
  cp "$SRC" "$DEST"
  echo "Copied addon to $DEST"
else
  curl -fsSL "$RAW_URL" -o "$DEST"
  echo "Downloaded addon to $DEST"
fi

if [ -f "$CONFIG" ] && grep -q "ga4_app_measurement.py" "$CONFIG"; then
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

echo
echo "Done. Start mitmweb and open a request to app-measurement.com/a."
echo "Filter GA4 requests with:  ~comment GA4"
