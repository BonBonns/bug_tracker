#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/build"
rm -rf "$BUILD" && mkdir -p "$BUILD"
javac -d "$BUILD" $(find "$ROOT/core/program_graph/src/main/java" -name '*.java' | sort) "$HERE/Gate25ProgramGraphTest.java"
java -cp "$BUILD" Gate25ProgramGraphTest
