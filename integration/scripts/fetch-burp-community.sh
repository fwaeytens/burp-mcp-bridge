#!/usr/bin/env bash
# Download the Burp Suite Community jar into a host cache once, so the
# integration stack can mount it read-only and never re-download per run.
#
# The jar is ~685 MB and licence-bound: it is deliberately NOT committed and NOT
# baked into any image. Cache location: ~/.cache/burp-mcp-bridge/.
set -euo pipefail

CACHE_DIR="${BURP_MCP_CACHE_DIR:-$HOME/.cache/burp-mcp-bridge}"
URL="https://portswigger.net/burp/releases/download?product=community&type=Jar"

mkdir -p "$CACHE_DIR"

# Already have one? Do nothing.
existing=$(ls "$CACHE_DIR"/burpsuite_community_v*.jar 2>/dev/null | head -1 || true)
if [ -n "$existing" ]; then
  echo "Burp Community jar already cached: $existing"
  exit 0
fi

echo "Downloading Burp Community jar to $CACHE_DIR (~685 MB, once)…"
# -J uses the server's Content-Disposition filename (burpsuite_community_v<ver>.jar).
tmp="$CACHE_DIR/.download.part"
curl -fL --retry 3 -o "$tmp" "$URL"

# Recover the versioned filename from the download, falling back to a generic one.
name=$(curl -fsI "$URL" | tr -d '\r' \
  | sed -n 's/.*filename=\(burpsuite_community_v[^;]*\.jar\).*/\1/p' | head -1)
name=${name:-burpsuite_community.jar}
mv "$tmp" "$CACHE_DIR/$name"
echo "Cached: $CACHE_DIR/$name"
