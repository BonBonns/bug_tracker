#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate34/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" "$ROOT/core/evidence/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate34/Gate34StateChannelTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate34StateChannelTest | tee "$ROOT/tests/gates/gate34/gate34_test.out"
