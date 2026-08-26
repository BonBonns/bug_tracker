#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreS01Test.java"
java -cp "$BUILD" CoreS01Test | tee "$HERE/core_s01.out"
grep -q 'CORE_S01=7/7' "$HERE/core_s01.out"
