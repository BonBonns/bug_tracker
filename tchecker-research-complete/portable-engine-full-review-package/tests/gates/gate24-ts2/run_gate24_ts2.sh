#!/usr/bin/env bash
# Gate 24-TS-2: corrected dispatch classification against REAL jssrc2cpg facts.
# Reuses gate24-ts's real-Joern export if present; otherwise runs it (requires JOERN/JSSRC2CPG).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RAW="$HERE/../gate24-ts/run/joern/raw"
if [[ ! -f "$RAW/methods.tsv" ]]; then
  echo "no raw facts; running gate24-ts first (needs real Joern)"
  (cd "$HERE/../gate24-ts" && bash run_gate24_ts.sh)
fi
python3 "$HERE/check_gate24_ts2.py" "$RAW" | tee "$HERE/gate24_ts2.out"
grep -q '^GATE24_TS2=18/18$' "$HERE/gate24_ts2.out"
