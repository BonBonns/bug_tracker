#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
node "$HERE/classify_calls.js" "$HERE/gate4.ts" > "$HERE/resolution_manifest.regen.json"
node "$HERE/tsclass2csv.js" "$HERE/gate4.ts" "$HERE/regen"
echo "Frontend Gate 4 regenerated. Compare resolution_manifest.regen.json with resolution_manifest.json."
echo "Real-engine verification in GATE4_RESULT.md was run against the existing compiled engine; engine classes are not bundled here."
