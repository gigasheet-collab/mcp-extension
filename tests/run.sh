#!/bin/bash
# Runs every suite against ./server with an isolated keychain service, a
# private lock directory, and the browser suppressed. Needs `node` on PATH
# (or NODE=/path/to/node). Nothing here touches the real credential.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE="${NODE:-node}"
export TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
fail=0
for t in tests/0*.js; do
  rm -f "$TMPDIR"/gigasheet-mcp-signin-* 2>/dev/null
  out=$("$NODE" "$t" server 2>&1 | grep -v '^\[gigasheet\]')
  if echo "$out" | grep -q "PASSED"; then echo "ok    $t"; else echo "FAIL  $t"; echo "$out" | grep "FAIL\|CRASH"; fail=1; fi
done
exit $fail
