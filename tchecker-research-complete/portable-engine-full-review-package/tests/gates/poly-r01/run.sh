#!/usr/bin/env bash
# POLY-R01: cross-language provenance graph — real C++ N-API core + real JS wrapper
# from ONE repository, merged into ONE graph, analyzed by the UNCHANGED loader/engine.
#
# NOT wired into tests/run_all.py: this gate clones a GitHub repository (network
# dependency), and the canonical suite must stay hermetic. Run it manually:
#   JOERN_HOME=/path/to/joern-cli bash run.sh [repo-dir]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME to joern-cli}"
BUILD="$HERE/../jsts-r05/build"
[ -d "$BUILD" ] || { echo "build jsts-r05 first"; exit 20; }
REPO="${1:-}"
if [ -z "$REPO" ]; then
  REPO="$(mktemp -d)/repo"
  git clone --depth 1 https://github.com/kelektiv/node.bcrypt.js.git "$REPO"
fi
W="$(mktemp -d /tmp/poly-r01.XXXXXX)"
mkdir -p "$W/csrc" "$W/craw" "$W/jssrc" "$W/jsraw"
cp "$REPO"/src/*.cc "$REPO"/src/*.h "$W/csrc/" 2>/dev/null || true
cp "$REPO"/bcrypt.js "$REPO"/promises.js "$W/jssrc/"
"$JH/c2cpg.sh" -o "$W/c.cpg" "$W/csrc" > "$W/gen.log" 2>&1
"$JH/joern" --script "$HERE/../cpp-r06/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$W/c.cpg" --param outDir="$W/craw" >> "$W/gen.log" 2>&1
python3 "$HERE/../cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$W/craw" "$W/cpp.json"
"$JH/jssrc2cpg.sh" "$W/jssrc" --output "$W/js.cpg.zip" >> "$W/gen.log" 2>&1
"$JH/joern" --script "$ROOT/frontends/javascript-typescript/joern-ts/export_ts_facts.sc" --param cpgFile="$W/js.cpg.zip" --param outDir="$W/jsraw" >> "$W/gen.log" 2>&1
python3 "$ROOT/frontends/javascript-typescript/joern-ts/normalize_ts_facts.py" "$W/jsraw" "$W/js.json"
java -cp "$BUILD" EndToEndRunner "$W/js.json" > "$W/js_only.out"
python3 "$HERE/merge_polyglot.py" "$W/cpp.json" "$W/js.json" "$W/merged.json"
echo '{"schema":"portable-state-facts/0.3","state_writes":[],"state_reads":[]}' > "$W/state.json"
echo '{"schema":"portable-identity-facts/0.2","bindings":[]}' > "$W/identity.json"
echo '{"schema":"portable-capture-facts/0.2","captures":[]}' > "$W/capture.json"
java -cp "$BUILD" EndToEndRunner "$W/merged.json" "$W/state.json" "$W/identity.json" "$W/capture.json" "$W/merged.json.crosslang.json" > "$W/merged.out"
python3 "$HERE/check_poly_r01.py" "$W/merged.json" "$W/merged.out" "$W/js_only.out"
echo "POLY_R01_ARTIFACT=$W"
