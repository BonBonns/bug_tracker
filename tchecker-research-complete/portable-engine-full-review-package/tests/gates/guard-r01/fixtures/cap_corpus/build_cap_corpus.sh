#!/usr/bin/env bash
# GUARD-R01 / task #42: rebuilds /tmp/cap_corpus deterministically from the COMMITTED sources in
# this directory (g.cpp, t3.cpp, t5.cpp), replacing the operator-maintained, never-committed
# fixture FIXTURE_NOTE.md records as lost. Real pipeline, same shape as
# tests/gates/cpp-param-r01/run.sh: c2cpg -> export_c_cpp_facts_v03.sc -> normalize (the
# normalizer's own main() writes g.json plus every *.destcapacity.json / *.srccapacity.json /
# *.operandrole.json / *.bound.json sidecar oob_write_controls.py / oob_read_controls.py read).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../../.." && pwd)"
JH="${JOERN_HOME:-$ROOT/joern-install/joern-cli}"
[ -x "$JH/c2cpg.sh" ] || { echo "no c2cpg.sh at $JH -- set JOERN_HOME" >&2; exit 20; }

OUT="${1:-/tmp/cap_corpus}"
mkdir -p "$OUT"

build_one() {
    local src_cpp="$1" out_name="$2"
    local w
    w="$(mktemp -d "/tmp/cap_corpus_build.XXXXXX")"
    mkdir -p "$w/src" "$w/raw"
    cp "$src_cpp" "$w/src/"
    "$JH/c2cpg.sh" -o "$w/cpg.bin" "$w/src" > "$w/gen.log" 2>&1
    "$JH/joern" --script "$ROOT/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc" \
        --param cpgFile="$w/cpg.bin" --param outDir="$w/raw" >> "$w/gen.log" 2>&1
    python3 "$ROOT/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py" \
        "$w/raw" "$OUT/$out_name.json"
    rm -rf "$w"
}

build_one "$HERE/g.cpp" "g"
build_one "$HERE/t3.cpp" "t3"
build_one "$HERE/t5.cpp" "t5"

echo "cap_corpus rebuilt at $OUT (g.json, t3.json, t5.json + sidecars)"
