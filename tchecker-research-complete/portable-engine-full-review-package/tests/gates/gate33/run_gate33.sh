#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$(dirname "$0")/out"
rm -rf "$OUT" && mkdir -p "$OUT"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" "$ROOT/core/evidence/src/main/java" -name '*.java' > "$OUT/sources.txt"
echo "$(dirname "$0")/Gate33RelationEvidenceTest.java" >> "$OUT/sources.txt"
javac -d "$OUT" @"$OUT/sources.txt"
java -cp "$OUT" Gate33RelationEvidenceTest | tee "$(dirname "$0")/gate33_test.out"
