#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate36/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" "$ROOT/core/effects/src/main/java" "$ROOT/core/evidence/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate36/Gate36RejectedIdeasRegressionTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate36RejectedIdeasRegressionTest | tee "$ROOT/tests/gates/gate36/gate36_test.out"
