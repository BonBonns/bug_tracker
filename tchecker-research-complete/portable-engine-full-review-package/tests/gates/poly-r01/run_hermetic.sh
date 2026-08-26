#!/usr/bin/env bash
# POLY-R01-H: hermetic cross-language gate (shipped fixtures, NO network).
# Proves end-to-end positional provenance across the JS<->C++ boundary through
# the UNCHANGED loader/engine, incl. the position-shuffle discriminator.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME to joern-cli}"
BUILD="$HERE/../jsts-r05/build"
[ -d "$BUILD" ] || { echo "build jsts-r05 first"; exit 20; }
W="$(mktemp -d /tmp/poly-r01-h.XXXXXX)"
mkdir -p "$W/csrc" "$W/craw" "$W/jssrc" "$W/jsraw"
cp "$HERE/fixtures/native.cc" "$W/csrc/"
cp "$HERE/fixtures/wrapper.js" "$W/jssrc/"
"$JH/c2cpg.sh" -o "$W/c.cpg" "$W/csrc" > "$W/gen.log" 2>&1
"$JH/joern" --script "$HERE/../cpp-r06/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$W/c.cpg" --param outDir="$W/craw" >> "$W/gen.log" 2>&1
python3 "$HERE/../cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$W/craw" "$W/cpp.json"
"$JH/jssrc2cpg.sh" "$W/jssrc" --output "$W/js.cpg.zip" >> "$W/gen.log" 2>&1
"$JH/joern" --script "$ROOT/frontends/javascript-typescript/joern-ts/export_ts_facts.sc" --param cpgFile="$W/js.cpg.zip" --param outDir="$W/jsraw" >> "$W/gen.log" 2>&1
python3 "$ROOT/frontends/javascript-typescript/joern-ts/normalize_ts_facts.py" "$W/jsraw" "$W/js.json"
python3 "$HERE/merge_polyglot.py" "$W/cpp.json" "$W/js.json" "$W/merged.json"
# the linkage rides ONLY in the crosslang fact family: full 5-doc chain, with
# empty (but schema-valid) state/identity/capture docs in between
echo '{"schema":"portable-state-facts/0.3","state_writes":[],"state_reads":[]}' > "$W/state.json"
echo '{"schema":"portable-identity-facts/0.2","bindings":[]}' > "$W/identity.json"
echo '{"schema":"portable-capture-facts/0.2","captures":[]}' > "$W/capture.json"
java -cp "$BUILD" EndToEndRunner "$W/merged.json" "$W/state.json" "$W/identity.json" "$W/capture.json" "$W/merged.json.crosslang.json" > "$W/merged.out"
python3 "$HERE/check_poly_hermetic.py" "$W/merged.json" "$W/merged.out"

# --- scenario 2: N-API marshalling (CallbackInfo slot reads -> positional flow) ---
M="$W/marshal"; mkdir -p "$M/csrc" "$M/craw" "$M/jssrc" "$M/jsraw"
cp "$HERE/fixtures/native_marshal.cc" "$M/csrc/"
cp "$HERE/fixtures/wrapper_marshal.js" "$M/jssrc/"
"$JH/c2cpg.sh" -o "$M/c.cpg" "$M/csrc" >> "$W/gen.log" 2>&1
"$JH/joern" --script "$HERE/../cpp-r06/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$M/c.cpg" --param outDir="$M/craw" >> "$W/gen.log" 2>&1
python3 "$HERE/../cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$M/craw" "$M/cpp.json"
"$JH/jssrc2cpg.sh" "$M/jssrc" --output "$M/js.cpg.zip" >> "$W/gen.log" 2>&1
"$JH/joern" --script "$ROOT/frontends/javascript-typescript/joern-ts/export_ts_facts.sc" --param cpgFile="$M/js.cpg.zip" --param outDir="$M/jsraw" >> "$W/gen.log" 2>&1
python3 "$ROOT/frontends/javascript-typescript/joern-ts/normalize_ts_facts.py" "$M/jsraw" "$M/js.json"
python3 "$HERE/merge_polyglot.py" "$M/cpp.json" "$M/js.json" "$M/merged.json"
java -cp "$BUILD" EndToEndRunner "$M/merged.json" "$W/state.json" "$W/identity.json" "$W/capture.json" "$M/merged.json.crosslang.json" > "$M/merged.out"
python3 "$HERE/check_poly_marshal.py" "$M/merged.json" "$M/merged.out"
echo "POLY_R01_H_ARTIFACT=$W"
