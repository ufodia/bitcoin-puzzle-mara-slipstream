#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="bitcoin-puzzle-mara-slipstream-v0.1.0-source"
DIST="$ROOT/dist"
STAGE="$DIST/$NAME"

rm -rf "$STAGE"
mkdir -p "$STAGE"

rsync -a \
  --exclude '.git' \
  --exclude 'target' \
  --exclude 'dist' \
  --exclude '*.swe' \
  --exclude '*.key' \
  --exclude '*.wif' \
  "$ROOT/" "$STAGE/"

(
  cd "$DIST"
  rm -f "$NAME.zip"
  zip -qr "$NAME.zip" "$NAME"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$NAME.zip" > "$NAME.zip.sha256"
  fi
)

echo "Created $DIST/$NAME.zip"
