#!/bin/bash
# scan_pkg.sh <src_dir> <out_dir> — build CPG + run all exporters. Diagnosable per-package.
#
# 2026-08-24 FIX: previously this script (a) hardcoded JOERN_HOME, (b) referenced
# module_export_identity.sc by a bundle-root-relative path while referencing the six
# detector exporters by bare name (flat-CWD-relative) — two mutually contradictory CWD
# assumptions, so no single working directory could resolve all seven scripts, and
# (c) suppressed all stderr AND printed "OK" unconditionally, so silent partial failure
# looked like success. Now every script is resolved by absolute path from this file's
# location, exporter failures are counted and reported, and a scan that produced no
# detector facts exits non-zero.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE="$(dirname "$HERE")"
JOERN_HOME="${JOERN_HOME:-/home/claude/work/joern-cli}"
JOERN="$JOERN_HOME/joern"
JSSRC2CPG="$JOERN_HOME/jssrc2cpg.sh"
PRShared="$BUNDLE/portable-engine-full-review-package/frontends/javascript-typescript/joern-ts"
PRDet="$BUNDLE/tchecker-property-adjudicator/producers"

SRC="$1"; OUT="$2"
mkdir -p "$OUT/raw"
[ -x "$JOERN" ] || { echo "NO_JOERN: $JOERN not found (set JOERN_HOME)"; exit 2; }

if ! "$JSSRC2CPG" "$SRC" --output "$OUT/cpg.bin" >"$OUT/build.log" 2>&1; then
  echo "BUILD_FAILED $SRC (see $OUT/build.log)"; tail -3 "$OUT/build.log"; exit 1
fi
[ -s "$OUT/cpg.bin" ] || { echo "NO_CPG $SRC"; tail -3 "$OUT/build.log"; exit 1; }

fail=0; ran=0
run_sc() { # <label> <abs-script>
  local label="$1" sc="$2"
  if [ ! -f "$sc" ]; then echo "  MISSING_SCRIPT $label ($sc)"; fail=$((fail+1)); return; fi
  if "$JOERN" --script "$sc" --param cpgFile="$OUT/cpg.bin" --param outDir="$OUT/raw" \
        >>"$OUT/export.log" 2>&1; then ran=$((ran+1));
  else echo "  EXPORT_FAILED $label (see $OUT/export.log)"; fail=$((fail+1)); fi
}

: > "$OUT/export.log"
run_sc module_export_identity "$PRShared/module_export_identity.sc"
for sc in export_guard_facts export_loop_facts export_denylist_facts \
          export_mal_facts export_globalmut_facts export_serialize_facts; do
  run_sc "$sc" "$PRDet/$sc.sc"
done

tsv=$(find "$OUT/raw" -name '*.tsv' | wc -l)
echo "$(basename "$OUT"): cpg=$(du -h "$OUT/cpg.bin"|cut -f1) exporters_ran=$ran failed=$fail tsv_files=$tsv"
[ "$ran" -gt 0 ] && [ "$fail" -eq 0 ]
