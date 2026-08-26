#!/usr/bin/env bash
# JS-PROP-R03: real jssrc2cpg -> canonical state facts -> neutral engine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"
RUN="$(mktemp -d /tmp/js-prop-r03.XXXXXX)"
mkdir -p "$RUN/src" "$RUN/raw" "$RUN/build"
cp "$HERE/fixture/nested_state_identity.js" "$RUN/src/"
"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1
python3 "$FR/normalize_ts_facts.py" "$RUN/raw" "$RUN/program.json"
python3 "$FR/state_facts.py" "$RUN/raw" "$RUN/state.json"
javac -d "$RUN/build" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$ROOT/tests/gates/jsts-r05/EndToEndRunner.java"
java -cp "$RUN/build" EndToEndRunner "$RUN/program.json" "$RUN/state.json" > "$RUN/engine.out"
python3 "$HERE/check_js_prop_r03.py" "$RUN/program.json" "$RUN/state.json" "$RUN/engine.out" | tee "$RUN/result.txt"
mkdir -p "$HERE/run"
cp "$RUN/program.json" "$RUN/state.json" "$RUN/engine.out" "$RUN/result.txt" "$HERE/run/"
grep -q '^JS_PROP_R03=16/16$' "$RUN/result.txt"
