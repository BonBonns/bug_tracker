#!/usr/bin/env bash
# Sink-provenance demo: "which input does the value reaching this
# security-relevant operand derive from?"  Only the sink operand changes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
JH="${JOERN_HOME:?set JOERN_HOME to your joern-cli directory}"
BUILD="$ROOT/tests/gates/jsts-r05/build"
[ -d "$BUILD" ] || { echo "build tests/gates/jsts-r05 first"; exit 20; }
for v in "$HERE"/variants/*.c; do
  n="$(basename "$v" .c)"
  W="$(mktemp -d /tmp/sinkdemo.XXXXXX)"; mkdir -p "$W/src" "$W/raw"; cp "$v" "$W/src/"
  "$JH/c2cpg.sh" -o "$W/cpg.bin" "$W/src" >/dev/null 2>&1
  "$JH/joern" --script "$ROOT/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc" \
      --param cpgFile="$W/cpg.bin" --param outDir="$W/raw" >/dev/null 2>&1
  python3 "$ROOT/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py" "$W/raw" "$W/p.json" >/dev/null
  echo "=== $n ==="
  SINKS="write_out:1,write_out:2" java -cp "$BUILD" EndToEndRunner "$W/p.json" \
      "$W/p.json.memory.json" "$W/p.json.expression.json" \
      "$W/p.json.reachingdef.json" "$W/p.json.source.json" 2>/dev/null | grep '^SINK' || true
  rm -rf "$W"
done
