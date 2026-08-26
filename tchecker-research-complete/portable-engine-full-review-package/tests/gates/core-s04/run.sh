#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreS04Test.java"
java -cp "$BUILD" CoreS04Test | tee "$HERE/core_s04.out"
grep -q 'CORE_S04=13/13' "$HERE/core_s04.out"
