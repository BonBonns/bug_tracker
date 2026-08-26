#!/usr/bin/env bash
# JS-REAL-R01 reproduction script. Re-stages the exact corpus scope used for
# this scan and re-runs the exact pipeline, unmodified from JS-STATE-R02..R05.
# Not a gate (no pass/fail check) -- a measurement pass. See JS_REAL_R01_VERDICT.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FR="$ROOT/frontends/javascript-typescript/joern-ts"
JSSRC2CPG="${JSSRC2CPG:?set JSSRC2CPG}"
JOERN="${JOERN:?set JOERN}"
FXA_REPO="${FXA_REPO:?set FXA_REPO to a checkout of https://github.com/mozilla/fxa at commit e856cffdbf261c0b73ff51cde86045f77d26044b}"

RUN="$(mktemp -d /tmp/js-real-r01.XXXXXX)"
mkdir -p "$RUN/corpus_src" "$RUN/raw"

# Phase 1: stage the exact, disclosed corpus scope.
for d in routes tokens crypto oauth; do
  cp -r "$FXA_REPO/packages/fxa-auth-server/lib/$d" "$RUN/corpus_src/"
done

# Phase 2: real frontend + real export (identical script to JS-STATE-R02..R05).
"$JSSRC2CPG" "$RUN/corpus_src" --output "$RUN/cpg.bin.zip" > "$RUN/gen.log" 2>&1
"$JOERN" --script "$FR/export_ts_facts.sc" --param cpgFile="$RUN/cpg.bin.zip" --param outDir="$RUN/raw" >> "$RUN/export.log" 2>&1

[ -s "$RUN/raw/methods.tsv" ] || { echo "FATAL: empty methods.tsv"; exit 30; }

# Phase 2 supplementary: closure + property/state facts (frontend-completeness measurement).
python3 "$FR/capture_facts.py" "$RUN/raw" > "$RUN/capture_facts.json"
python3 "$FR/state_facts.py" "$RUN/raw" > "$RUN/state_facts.json"

# Phase 3: JS-STATE, unchanged.
python3 "$FR/failure_state_facts.py" "$RUN/raw" > "$RUN/failure_state_facts.json"
python3 "$FR/security_sensitive_reachability.py" "$RUN/raw" > "$RUN/sink_reachability.json"

echo "Facts written to: $RUN"
echo "Compare against docs/corpus-scans/js-real-r01/evidence/failure_state_facts.json and sink_reachability.json"
