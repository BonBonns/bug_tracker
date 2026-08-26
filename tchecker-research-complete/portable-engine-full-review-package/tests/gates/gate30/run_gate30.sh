#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate30/out"
rm -rf "$OUT"; mkdir -p "$OUT"
find "$ROOT/core/effects/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate30/Gate30TransformationEffectsTest.java" >> "$OUT/sources.txt"
javac -encoding UTF-8 -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate30TransformationEffectsTest | tee "$ROOT/tests/gates/gate30/gate30_test.out"
grep -q 'GATE30=13/13' "$ROOT/tests/gates/gate30/gate30_test.out"
grep -q 'ANALYSIS_STATUS=COMPLETE' "$ROOT/tests/gates/gate30/gate30_test.out"
