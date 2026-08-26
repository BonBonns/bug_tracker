#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreMemoryTest.java"
java -cp "$BUILD" CoreMemoryTest | tee "$HERE/core_memory.out"
grep -q 'CORE_MEMORY=5/5' "$HERE/core_memory.out"
