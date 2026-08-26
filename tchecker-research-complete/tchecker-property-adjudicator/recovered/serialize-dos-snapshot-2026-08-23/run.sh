#!/usr/bin/env bash
# End-to-end serialize-DoS adjudication on a single JS/TS file.
# Usage: ./run.sh <file.js|dir> <source_pattern> [sink_index]
#   e.g. ./run.sh fixtures/demo_member_transform.js "req.body"
# Requires: JOERN_HOME pointing at an installed Joern 4.x (jssrc2cpg + joern on PATH via $JOERN_HOME/bin).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${JOERN_HOME:?Set JOERN_HOME to your Joern install (e.g. export JOERN_HOME=/opt/joern/joern-cli)}"
SRCFILE="$1"; PATTERN="${2:-req.body}"
WORK="$(mktemp -d)"; RAW="$WORK/raw"; mkdir -p "$RAW"
# 1. build CPG (jssrc2cpg handles .js and .ts)
INPUT="$SRCFILE"; [ -f "$SRCFILE" ] && { mkdir -p "$WORK/src"; cp "$SRCFILE" "$WORK/src/"; INPUT="$WORK/src"; }
"$JOERN_HOME/jssrc2cpg.sh" "$INPUT" --output "$WORK/cpg.bin" >/dev/null 2>&1
echo "[1/4] CPG built"
# 2. detect sink/source/transforms
"$JOERN_HOME/joern" --script "$HERE/producers/setup_candidate.sc" \
  --param cpgFile="$WORK/cpg.bin" --param rawDir="$RAW" --param srcPattern="$PATTERN" 2>/dev/null | grep SETUP_CANDIDATE || true
# 3. property-propagation + trace-identity layers
"$JOERN_HOME/joern" --script "$HERE/producers/export_property_propagation.sc" \
  --param cpgFile="$WORK/cpg.bin" --param rawDir="$RAW" 2>/dev/null | grep OUTCOME || true
"$JOERN_HOME/joern" --script "$HERE/producers/export_trace_identity.sc" \
  --param cpgFile="$WORK/cpg.bin" --param rawDir="$RAW" 2>/dev/null | grep -E "TRACE_IDENTITY (call|COMPLETE)" || true
echo "[3/4] property + identity layers done"
# 4. adjudicate (first sink)
SINK=$(cut -f1 "$RAW/source_facts.tsv")
echo "[4/4] adjudication:"
TCH_HINTS="${TCH_HINTS:-$HERE/no_hints.json}" \
  TCH_RAW="$RAW" TCH_SRC="$WORK/src" TCH_OUT="$WORK/out" TCH_SINK="$SINK" TCH_FINDING="$(basename "$SRCFILE")" \
  python3 "$HERE/adjudicator/adjudicate_js.py" 2>&1 | grep -E "FINAL" || true
python3 - "$WORK/out/evidence_final.json" <<'PY'
import json,sys
e=json.load(open(sys.argv[1]))
print("   property_outcome :", e["property_outcome"])
print("   disposition      :", e["disposition"])
pv=e.get("property_vs_vulnerability")
if pv: print("   note             :", pv["established"])
PY
echo "artifacts in: $WORK"
