#!/usr/bin/env bash
# SOURCE-R02c2: source-target recognition. Proves the four target cases and that
# the MAY-alias / pointer-variable controls can actually fail.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME}"
W="$(mktemp -d /tmp/source-r02.XXXXXX)"; mkdir -p "$W/src" "$W/raw"
cp "$HERE/fixtures/shapes.cpp" "$W/src/"
"$JH/c2cpg.sh" -o "$W/cpg.bin" "$W/src" > "$W/gen.log" 2>&1
"$JH/joern" --script "$ROOT/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc" --param cpgFile="$W/cpg.bin" --param outDir="$W/raw" >> "$W/gen.log" 2>&1
python3 "$ROOT/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$W/raw" "$W/program.json"
if [ -z "${SOURCE_R02E_OFF:-}" ]; then
  # Fail LOUDLY if the engine crashes instead of swallowing it: a silent crash here
  # previously showed up downstream as six mysteriously-unrenderable [None] teeth in
  # check_source_r02c2.py rather than the real exception (see MEMORY_LOCATION enum
  # mismatch fixed 2026-08-26).
  if ! SINKS="sink:0" java -cp "$ROOT/tests/gates/jsts-r05/build" EndToEndRunner "$W/program.json" \
    "$W/program.json.memory.json" "$W/program.json.expression.json" \
    "$W/program.json.reachingdef.json" "$W/program.json.source.json" > "$W/sink.out" 2>"$W/sink.err"; then
    echo "FATAL: EndToEndRunner crashed — see stderr below" >&2
    cat "$W/sink.err" >&2
    exit 21
  fi
  export SINK_OUT="$W/sink.out"
fi
python3 "$HERE/check_source_r02c2.py" "$W"
