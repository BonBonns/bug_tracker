#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then echo "usage: $0 <typescript-source-dir> <out-dir>" >&2; exit 2; fi
SRC="$(cd "$1" && pwd)"; OUT="$2"; mkdir -p "$OUT/raw"
JSSRC2CPG="${JSSRC2CPG:-$(command -v jssrc2cpg || true)}"
JOERN="${JOERN:-$(command -v joern || true)}"
[ -n "$JSSRC2CPG" ] || { echo "REAL_JOERN_TS_BLOCKED: jssrc2cpg not found" >&2; exit 20; }
[ -n "$JOERN" ] || { echo "REAL_JOERN_TS_BLOCKED: joern not found" >&2; exit 21; }
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CPG="$OUT/cpg.bin"
# Do NOT pass --no-tsTypes: this gate is specifically measuring Joern's TS type generation.
"$JSSRC2CPG" "$SRC" --output "$CPG"
"$JOERN" --script "$ROOT/frontends/javascript-typescript/joern-ts/export_ts_facts.sc" --param cpgFile="$CPG" --param outDir="$OUT/raw"
python3 "$ROOT/frontends/javascript-typescript/joern-ts/normalize_ts_facts.py" "$OUT/raw" "$OUT/typescript_facts.json"
echo "REAL_JOERN_TS_COMPLETE: $OUT/typescript_facts.json"
