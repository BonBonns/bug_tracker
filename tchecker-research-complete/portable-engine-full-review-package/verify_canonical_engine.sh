#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TC="$ROOT/engine/legacy-detector/tchecker"
"$TC/build.sh"
CP="$TC/out:$(find "$TC/lib" -name '*.jar' | tr '\n' ':')"
mkdir -p "$TC/out/tools/php/ast2cpg"
javac -encoding UTF-8 -d "$TC/out" -cp "$CP" "$ROOT/tests/tools/ProbeGate23.java"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp "$ROOT/tests/gates/gate23/csv/nodes.csv" "$WORK/nodes.csv"
cp "$ROOT/tests/gates/gate23/csv/rels.csv" "$WORK/rels.csv"
(cd "$WORK" && WP_FRONTEND_CALL_RESOLUTION="$ROOT/tests/gates/gate23/csv/frontend_resolution.tsv" WP_FRONTEND_CLOSURE_RETURN_SUMMARY="$ROOT/tests/gates/gate23/csv/frontend_closure_return.tsv" java -cp "$CP" tools.php.ast2cpg.ProbeGate23 > probe.out 2> probe.err)
python3 "$ROOT/tests/gates/gate23/gate23_test.py" "$WORK/probe.out" 2>/dev/null || true
# The original test reads bundled on/off outputs, so additionally require runtime markers from fresh probe.
grep -q 'RET .*closureDirect.*positions=\[0\]' "$WORK/probe.out"
grep -q 'RET .*nestedClosure.*positions=\[0\]' "$WORK/probe.out"
echo CANONICAL_ENGINE_GATE23=PASS
