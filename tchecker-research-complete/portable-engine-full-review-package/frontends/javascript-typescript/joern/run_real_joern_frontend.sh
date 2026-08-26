#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:?usage: $0 <js-ts-source-dir> <out-dir>}"
OUT="${2:?usage: $0 <js-ts-source-dir> <out-dir>}"
JSSRC2CPG="${JSSRC2CPG:-$(command -v jssrc2cpg || true)}"
JOERN="${JOERN:-$(command -v joern || true)}"
if [[ -z "$JSSRC2CPG" || ! -x "$JSSRC2CPG" ]]; then
  echo "REAL_JOERN_BLOCKED: jssrc2cpg executable not found (set JSSRC2CPG=/path/to/jssrc2cpg)" >&2
  exit 20
fi
if [[ -z "$JOERN" || ! -x "$JOERN" ]]; then
  echo "REAL_JOERN_BLOCKED: joern executable not found (set JOERN=/path/to/joern)" >&2
  exit 21
fi
mkdir -p "$OUT/raw"
CPG="$OUT/cpg.bin.zip"
"$JSSRC2CPG" "$SRC" --output "$CPG"
"$JOERN" --script "$HERE/export_neutral.sc" --param "cpgFile=$CPG" --param "outDir=$OUT/raw"
python3 "$HERE/normalize_joern_facts.py" "$OUT/raw" "$OUT/program_facts.json"
echo "REAL_JOERN_FRONTEND_COMPLETE=$OUT/program_facts.json"
