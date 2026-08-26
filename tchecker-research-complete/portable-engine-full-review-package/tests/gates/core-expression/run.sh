#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreExpressionTest.java"
java -cp "$BUILD" CoreExpressionTest | tee "$HERE/core_expression.out"
grep -q 'CORE_EXPRESSION=5/5' "$HERE/core_expression.out"
