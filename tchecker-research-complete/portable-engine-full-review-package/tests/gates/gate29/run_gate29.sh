#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate29/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" "$ROOT/core/evidence/src/main/java" -name '*.java' -print > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate29/Gate29TypedEvidenceTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate29TypedEvidenceTest | tee "$ROOT/tests/gates/gate29/gate29_test.out"
grep -q 'GATE29=15/15' "$ROOT/tests/gates/gate29/gate29_test.out"
grep -q 'ANALYSIS_STATUS=COMPLETE' "$ROOT/tests/gates/gate29/gate29_test.out"
