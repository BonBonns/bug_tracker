#!/usr/bin/env bash
# JS-STATE-R02: real jssrc2cpg -> real export (incl. the JS-STATE-R02 control-
# structure/condition-identifier facts promoted into export_ts_facts.sc) ->
# failure_state_facts.py -> check_js_state_r02.py. No stored/pre-computed
# fixtures are graded; everything here is freshly computed against the real
# Joern frontend.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"

RUN="$(mktemp -d /tmp/js-state-r02.XXXXXX)"
mkdir -p "$RUN/src" "$RUN/raw"
cp "$HERE/fixture/state_erasure.ts" "$RUN/src/"

"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1

[ -s "$RUN/raw/methods.tsv" ] || { echo "FATAL: empty methods.tsv — jssrc2cpg ignored the sources"; exit 30; }
[ -s "$RUN/raw/control_structures.tsv" ] || { echo "FATAL: empty control_structures.tsv — JS-STATE-R02 export missing"; exit 31; }

python3 "$HERE/check_js_state_r02.py" "$RUN/raw" | tee "$RUN/result.txt"
mkdir -p "$HERE/run"
cp "$RUN/result.txt" "$HERE/run/" 2>/dev/null || true
cp -r "$RUN/raw" "$HERE/run/raw" 2>/dev/null || true

grep -q "^JS_STATE_R02=" "$RUN/result.txt"
PASSED=$(grep "^JS_STATE_R02=" "$RUN/result.txt" | sed 's/JS_STATE_R02=//')
NUM=$(echo "$PASSED" | cut -d/ -f1)
DEN=$(echo "$PASSED" | cut -d/ -f2)
[ "$NUM" = "$DEN" ]
