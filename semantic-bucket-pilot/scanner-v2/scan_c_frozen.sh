#!/bin/bash
set -uo pipefail
SRC="$1"; OUT="$2"
F=$REPO/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend
mkdir -p "$OUT/raw"
/tmp/joern-cli/c2cpg.sh "$SRC" -o "$OUT/cpg.bin" >"$OUT/build.log" 2>&1 || { echo BUILD_FAIL; tail -3 "$OUT/build.log"; exit 1; }
/tmp/joern-cli/joern --script "$F/export_c_cpp_facts_v03.sc" --param cpgFile="$OUT/cpg.bin" --param outDir="$OUT/raw" >"$OUT/export.log" 2>&1 || { echo EXPORT_FAIL; tail -3 "$OUT/export.log"; exit 1; }
python3 "$F/normalize_c_cpp_facts_v03.py" "$OUT/raw" "$OUT/cpp.json" >"$OUT/norm.log" 2>&1 || { echo NORM_FAIL; tail -3 "$OUT/norm.log"; exit 1; }
echo "OK cpp.json $(wc -c < "$OUT/cpp.json") bytes"
