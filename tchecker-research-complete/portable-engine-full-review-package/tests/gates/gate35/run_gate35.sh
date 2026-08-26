#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/gates/gate35/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/runtime/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$ROOT/tests/gates/gate35/Gate35MeasurementHarnessTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate35MeasurementHarnessTest | tee "$ROOT/tests/gates/gate35/gate35_test.out"
