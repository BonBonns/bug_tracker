#!/usr/bin/env bash
# JS-STATE-R07: real jssrc2cpg -> real export -> js_state_r07.py ->
# check_js_state_r07.py. Nothing here is graded from a stored/pre-computed
# fixture.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"

RUN="$(mktemp -d /tmp/js-state-r07.XXXXXX)"
mkdir -p "$RUN/src" "$RUN/raw"
cp "$HERE/fixture/r07_fixture.ts" "$RUN/src/"

"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1

[ -s "$RUN/raw/methods.tsv" ] || { echo "FATAL: empty methods.tsv — jssrc2cpg ignored the sources"; exit 30; }
[ -s "$RUN/raw/type_hints.tsv" ] || { echo "FATAL: empty type_hints.tsv — Signal B has no data"; exit 31; }

python3 "$HERE/check_js_state_r07.py" "$RUN/raw" | tee "$RUN/result.txt"
mkdir -p "$HERE/run"
cp "$RUN/result.txt" "$HERE/run/" 2>/dev/null || true
cp -r "$RUN/raw" "$HERE/run/raw" 2>/dev/null || true

grep -q "^JS_STATE_R07=" "$RUN/result.txt"
PASSED=$(grep "^JS_STATE_R07=" "$RUN/result.txt" | sed 's/JS_STATE_R07=//')
NUM=$(echo "$PASSED" | cut -d/ -f1)
DEN=$(echo "$PASSED" | cut -d/ -f2)
[ "$NUM" = "$DEN" ]
