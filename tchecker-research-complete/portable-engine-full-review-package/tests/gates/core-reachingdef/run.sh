#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreReachingDefTest.java"
java -cp "$BUILD" CoreReachingDefTest | tee "$HERE/core_reachingdef.out"
grep -q 'CORE_REACHINGDEF=7/7' "$HERE/core_reachingdef.out"
