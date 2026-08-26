#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"; JOERN="${JOERN:?set JOERN}"
RUN="$(mktemp -d /tmp/js-prov-r21.XXXXXX)"; mkdir -p "$RUN/src" "$RUN/raw"
cp "$HERE/fixture/t.ts" "$RUN/src/"
"$JSSRC2CPG" "$RUN/src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
for S in parameter_decorators.sc local_definitions.sc; do
  "$JOERN" --script "$HERE/$S" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/gen.log" 2>&1
done
[ -s "$RUN/raw/param_decorators.tsv" ] || { echo "FATAL: empty param_decorators.tsv"; exit 30; }
python3 "$HERE/check_js_prov_r21.py" "$RUN/raw" | tee "$RUN/result.txt"
mkdir -p "$HERE/run"; cp "$RUN/result.txt" "$HERE/run/" 2>/dev/null || true
P=$(grep "^JS_PROV_R21=" "$RUN/result.txt" | sed 's/JS_PROV_R21=//')
[ "$(echo $P|cut -d/ -f1)" = "$(echo $P|cut -d/ -f2)" ]
