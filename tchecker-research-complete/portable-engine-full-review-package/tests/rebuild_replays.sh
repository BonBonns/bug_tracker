#!/usr/bin/env bash
# Rebuild the replay corpus from fixture sources through the REAL pipeline.
# Needs: JSSRC2CPG, JOERN env vars; node with the TypeScript lib for union sidecars.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
SIDE="$ROOT/frontends/javascript-typescript/tsc-sidecar/tsc_union_types.js"
OUT="${REPLAY_DIR:-/tmp/replay}"
for fx in 03 04 05 07 08 09 10 12 13 15 16 17 20 21 22 23; do
  src=$(ls "$ROOT/tests/gates/gate$fx"/gate*.ts "$ROOT/tests/gates/gate$fx"/gate*.js 2>/dev/null | head -1)
  [ -n "$src" ] || continue
  g="g$fx"; W="$OUT/$g"; rm -rf "$W"; mkdir -p "$W/src" "$W/raw"
  cp "$src" "$W/src/"
  "$JSSRC2CPG" "$W/src" --output "$W/cpg.bin.zip" > "$W/gen.log" 2>&1
  "$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$W/cpg.bin.zip" --param outDir="$W/raw" >> "$W/gen.log" 2>&1
  node "$SIDE" "$W/src" "$W/raw/union_hints.tsv" >/dev/null 2>&1 || true
  python3 "$FR/normalize_ts_facts.py" "$W/raw" "$W/program_facts.json"
  python3 "$FR/state_facts.py" "$W/raw" "$W/state_facts.json"
  python3 -c "import sys,json; sys.path.insert(0,'$FR'); from identity_facts import derive_identities; json.dump(derive_identities('$W/raw'), open('$W/identity_facts.json','w'))"
  python3 "$FR/capture_facts.py" "$W/raw" > "$W/capture_facts.json"
  echo "$g rebuilt"
done
