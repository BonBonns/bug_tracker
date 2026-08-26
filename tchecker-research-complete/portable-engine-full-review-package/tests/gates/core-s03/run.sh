#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreS03Test.java"
java -cp "$BUILD" CoreS03Test | tee "$HERE/core_s03.out"
grep -q 'CORE_S03=5/5' "$HERE/core_s03.out"
