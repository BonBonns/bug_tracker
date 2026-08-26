#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate31/out"
rm -rf "$OUT"; mkdir -p "$OUT"
find "$ROOT/core/effects/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate31/Gate31StructureAwareEffectsTest.java" >> "$OUT/sources.txt"
javac -encoding UTF-8 -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate31StructureAwareEffectsTest | tee "$ROOT/tests/gates/gate31/gate31_test.out"
grep -q 'GATE31=15/15' "$ROOT/tests/gates/gate31/gate31_test.out"
grep -q 'ANALYSIS_STATUS=COMPLETE' "$ROOT/tests/gates/gate31/gate31_test.out"
