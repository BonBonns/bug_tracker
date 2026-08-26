#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"; rm -rf "$BUILD"; mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core" -name '*.java' -path '*src/main*') "$HERE/CoreCrossLangTest.java"
java -cp "$BUILD" CoreCrossLangTest | tee "$HERE/core_crosslang.out"
grep -q 'CORE_CROSSLANG=5/5' "$HERE/core_crosslang.out"
