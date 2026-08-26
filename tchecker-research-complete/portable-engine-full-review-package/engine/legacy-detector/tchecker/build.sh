#!/usr/bin/env bash
# Build the TChecker detector (plain javac, no gradle/maven needed).
# Requires: a JDK (javac/java), version 8 or newer.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/detector"

JARS="$(find "$HERE/lib" -name '*.jar' | tr '\n' ':')"
OUT="$HERE/out"
mkdir -p "$OUT"

echo "[build] compiling detector -> $OUT"
javac -encoding UTF-8 -d "$OUT" -cp "$JARS" \
  -sourcepath "jpanlib/src/main/java:joern/src/main/java:joern-php/src/main/java" \
  joern-php/src/main/java/tools/php/ast2cpg/Main.java

echo "[build] done. classes in $OUT"
