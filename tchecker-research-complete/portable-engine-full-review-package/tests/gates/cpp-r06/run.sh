#!/usr/bin/env bash
# CPP-R06: real C/C++ -> c2cpg -> C/C++ frontend -> the UNCHANGED ProgramGraphLoader
# and PortableProvenanceEngine from JSTS-R05. The multilingual proof: two frontends,
# one contract, one loader, one engine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME to joern-cli}"
BUILD="$HERE/../jsts-r05/build"
[ -d "$BUILD" ] || { echo "build jsts-r05 first"; exit 20; }
for SRC in "$HERE/fixtures/app.c" "$HERE/fixtures/app.cpp"; do
  W="$HERE/.work-$(basename "$SRC" | tr . -)"; rm -rf "$W"; mkdir -p "$W/raw"
  "$JH/c2cpg.sh" -o "$W/cpg.bin" "$SRC" > "$W/gen.log" 2>&1
  "$JH/joern" --script "$HERE/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$W/cpg.bin" --param outDir="$W/raw" >> "$W/gen.log" 2>&1
  python3 "$HERE/frontend/normalize_c_cpp_facts_v03.py" "$W/raw" "$W/program.json"
  python3 "$HERE/tests/check_loader_contract.py" "$W/program.json" > "$W/contract.out"
  java -cp "$BUILD" EndToEndRunner "$W/program.json" > "$W/e2e.out"
done
python3 "$HERE/check_cpp_r06.py" "$HERE/.work-app-c/e2e.out" "$HERE/.work-app-cpp/e2e.out"
