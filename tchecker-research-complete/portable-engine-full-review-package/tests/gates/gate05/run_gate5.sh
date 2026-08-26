#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
node "$HERE/classify_calls.js" "$HERE/gate5.ts" > "$HERE/resolution_manifest.regen.json"
node "$HERE/tsclass2csv.js" "$HERE/gate5.ts" "$HERE/regen"
echo "Gate 5 frontend + CSV regenerated. Real-engine probe result is documented in GATE5_RESULT.md."
