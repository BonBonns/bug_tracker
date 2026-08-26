#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME}"; BUILD="$ROOT/tests/gates/jsts-r05/build"
W="$(mktemp -d /tmp/sink-r01.XXXXXX)"; mkdir -p "$W/src" "$W/raw"
cp "$HERE/fixtures/sink.cpp" "$W/src/"
"$JH/c2cpg.sh" -o "$W/cpg.bin" "$W/src" > "$W/gen.log" 2>&1
"$JH/joern" --script "$ROOT/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$W/cpg.bin" --param outDir="$W/raw" >> "$W/gen.log" 2>&1
python3 "$ROOT/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$W/raw" "$W/program.json"
SINKS="sink:0,sink:1" java -cp "$BUILD" EndToEndRunner "$W/program.json" "$W/program.json.memory.json" \
  "$W/program.json.expression.json" "$W/program.json.reachingdef.json" > "$W/out.txt"
python3 "$HERE/check_sink_r01.py" "$W/out.txt"
