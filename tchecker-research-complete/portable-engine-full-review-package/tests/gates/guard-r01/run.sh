#!/usr/bin/env bash
# GUARD-R01: every soundness-critical guard must FAIL on a known-bad input.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
[ -d "$ROOT/tests/gates/jsts-r05/build" ] || { echo "build jsts-r05 first"; exit 20; }
[ -f /tmp/cmp2/program.json ] && [ -f /tmp/pp2/program.json ] || { echo "GUARD-R01 BLOCKED: fixtures absent (run cpp-param-r01 and the comparative corpus first)"; exit 20; }
python3 "$ROOT/tools/guard_controls.py"
python3 "$ROOT/tools/guard_r02.py"
python3 "$ROOT/tools/status_r02_controls.py"
python3 "$ROOT/tools/status_r03_controls.py"
python3 "$ROOT/tools/status_norm_gate.py"
python3 "$ROOT/tools/keyselector_controls.py"
python3 "$ROOT/tools/js_source_r01_controls.py"
python3 "$ROOT/tools/origin_kind_purity_controls.py"
python3 "$ROOT/tools/origin_kind_corpus_purity.py"
python3 "$ROOT/tools/operand_role_controls.py"
python3 "$ROOT/tools/capacity_controls.py"
python3 "$ROOT/tools/bound_controls.py"
python3 "$ROOT/tools/oob_write_controls.py"
python3 "$ROOT/tools/oob_read_controls.py"
