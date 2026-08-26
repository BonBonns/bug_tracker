#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"
rm -rf "$BUILD" && mkdir -p "$BUILD"
javac -d "$BUILD" \
  $(find "$ROOT/core/program_graph/src/main/java" -name '*.java' | sort) \
  $(find "$ROOT/core/provenance-neutral/src/main/java" -name '*.java' | sort) \
  "$HERE/Gate27CorrectnessContractTest.java"
java -cp "$BUILD" Gate27CorrectnessContractTest | tee "$HERE/gate27_test.out"
grep -q '^GATE27=12/12$' "$HERE/gate27_test.out"
grep -q '^ANALYSIS_STATUS=COMPLETE$' "$HERE/gate27_test.out"
