#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate32/out"
rm -rf "$OUT"; mkdir -p "$OUT"
find "$ROOT/core/effects/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate32/Gate32ContextStackTest.java" >> "$OUT/sources.txt"
javac -encoding UTF-8 -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate32ContextStackTest | tee "$ROOT/tests/gates/gate32/gate32_test.out"
grep -q 'GATE32=13/13' "$ROOT/tests/gates/gate32/gate32_test.out"
grep -q 'ANALYSIS_STATUS=COMPLETE' "$ROOT/tests/gates/gate32/gate32_test.out"
