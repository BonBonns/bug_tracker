#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreS05Test.java"
java -cp "$BUILD" CoreS05Test | tee "$HERE/core_s05.out"
grep -q 'CORE_S05=7/7' "$HERE/core_s05.out"
