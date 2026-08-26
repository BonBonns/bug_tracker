#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BUILD="${TMPDIR:-/tmp}/portable_gate37_build"
rm -rf "$BUILD" && mkdir -p "$BUILD"
find "$ROOT/core/program_graph/src/main/java" "$ROOT/core/provenance-neutral/src/main/java" -name '*.java' -print0 | xargs -0 javac -d "$BUILD"
javac -cp "$BUILD" -d "$BUILD" "$ROOT/tests/gates/gate37/Gate37PerformanceHygieneTest.java"
java -cp "$BUILD" Gate37PerformanceHygieneTest
python3 "$ROOT/tests/gates/gate37/audit_portable_core.py"
