#!/usr/bin/env bash
# JSTS-R05: source -> real Joern -> neutral facts -> ProgramGraphLoader -> engine -> evidence.
# No PHPCGFactory anywhere in this pipeline.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"
# jssrc2cpg SILENTLY IGNORES sources whose names match test patterns (MEASURED: e2e.ts
# ignored, app.ts accepted — AstGenRunner default ignores). Neutral temp dir + loud empty-check.
RUN="$(mktemp -d /tmp/jsts-r05.XXXXXX)"; mkdir -p "$RUN/src" "$RUN/raw"
cp "$HERE/fixture/app.ts" "$RUN/src/"
"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1
# fail LOUDLY if the frontend silently exported nothing
[ -s "$RUN/raw/methods.tsv" ] || { echo "FATAL: empty methods.tsv — jssrc2cpg ignored the sources"; exit 30; }
python3 "$FR/normalize_ts_facts.py" "$RUN/raw" "$RUN/program_facts.json"
python3 "$FR/state_facts.py" "$RUN/raw" "$RUN/state_facts.json"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" \
  $(find "$ROOT/core/program_graph/src/main/java" -name '*.java' | sort) \
  $(find "$ROOT/core/provenance-neutral/src/main/java" -name '*.java' | sort) \
  $(find "$ROOT/core/evidence/src/main/java" -name '*.java' | sort) \
  "$HERE/EndToEndRunner.java"
java -cp "$BUILD" EndToEndRunner "$RUN/program_facts.json" "$RUN/state_facts.json" | tee "$RUN/e2e.out"
mkdir -p "$HERE/run"; cp "$RUN/e2e.out" "$RUN/program_facts.json" "$HERE/run/" 2>/dev/null || true
python3 "$HERE/check_jsts_r05.py" "$RUN/e2e.out"
