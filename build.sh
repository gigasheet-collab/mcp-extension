#!/bin/bash
# Packs the extension into dist/gigasheet.mcpb
#
# An .mcpb is a zip with manifest.json at the root. If the `mcpb` CLI is
# available we use it (it validates the manifest); otherwise we zip directly.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p dist
rm -f dist/gigasheet.mcpb

# A Node binary for validation: PATH first, then a dev-only fallback.
NODE="${NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] && [ -n "${NODE_FALLBACK:-}" ]; then NODE="$NODE_FALLBACK"; fi

python3 -c 'import json,sys; json.load(open("manifest.json"))' \
  || { echo "manifest.json is not valid JSON"; exit 1; }

if [ -n "$NODE" ]; then
  for f in server/index.js server/auth.js server/keychain.js server/env.js; do
    "$NODE" --check "$f" || { echo "$f does not parse"; exit 1; }
  done
else
  echo "warning: no node binary found; skipping syntax check"
fi

MCPB="${MCPB:-$(command -v mcpb || true)}"
if [ -n "$MCPB" ]; then
  "$MCPB" pack . dist/gigasheet.mcpb
else
  echo "mcpb CLI not found (npm i -g @anthropic-ai/mcpb); zipping directly"
  zip -q dist/gigasheet.mcpb manifest.json README.md icon.png \
    server/index.js server/auth.js server/keychain.js server/env.js
fi

echo "built dist/gigasheet.mcpb ($(du -h dist/gigasheet.mcpb | cut -f1))"
