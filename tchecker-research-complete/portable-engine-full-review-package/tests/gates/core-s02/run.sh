#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreS02Test.java"
java -cp "$BUILD" CoreS02Test | tee "$HERE/core_s02.out"
grep -q 'CORE_S02=6/6' "$HERE/core_s02.out"
