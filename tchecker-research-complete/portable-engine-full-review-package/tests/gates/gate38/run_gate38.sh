#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$ROOT/tests/gates/gate38"
OUT="$HERE/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" "$ROOT/core/evidence/src/main/java" "$ROOT/core/effects/src/main/java" "$ROOT/core/consumer/src/main/java" -name '*.java' | sort > "$OUT/sources.txt"
echo "$HERE/Gate38DeterministicConsumerTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate38DeterministicConsumerTest | tee "$HERE/gate38_test.out"
