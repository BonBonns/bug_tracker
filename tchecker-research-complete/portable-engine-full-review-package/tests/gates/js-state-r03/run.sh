#!/usr/bin/env bash
# JS-STATE-R03: real jssrc2cpg -> real export -> failure_state_facts.py ->
# security_sensitive_reachability.py -> check_js_state_r03.py. Same fixture as
# JS-STATE-R02 (reused, not duplicated logic); nothing here is graded from a
# stored/pre-computed fixture.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"

RUN="$(mktemp -d /tmp/js-state-r03.XXXXXX)"
mkdir -p "$RUN/src" "$RUN/raw"
cp "$HERE/fixture/state_erasure.ts" "$RUN/src/"

"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1

[ -s "$RUN/raw/methods.tsv" ] || { echo "FATAL: empty methods.tsv — jssrc2cpg ignored the sources"; exit 30; }
[ -s "$RUN/raw/control_structures.tsv" ] || { echo "FATAL: empty control_structures.tsv — JS-STATE-R02 export missing"; exit 31; }

python3 "$HERE/check_js_state_r03.py" "$RUN/raw" | tee "$RUN/result.txt"
mkdir -p "$HERE/run"
cp "$RUN/result.txt" "$HERE/run/" 2>/dev/null || true
cp -r "$RUN/raw" "$HERE/run/raw" 2>/dev/null || true

grep -q "^JS_STATE_R03=" "$RUN/result.txt"
PASSED=$(grep "^JS_STATE_R03=" "$RUN/result.txt" | sed 's/JS_STATE_R03=//')
NUM=$(echo "$PASSED" | cut -d/ -f1)
DEN=$(echo "$PASSED" | cut -d/ -f2)
[ "$NUM" = "$DEN" ]
