#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
python3 "$ROOT/tools/js_source_r03_controls.py" | tee "$HERE/js_source_r03.out"
grep -q 'JS_SOURCE_R03_CONTROLS=11/11' "$HERE/js_source_r03.out"
