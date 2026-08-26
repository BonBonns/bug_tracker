#!/bin/bash
# scan_pkg_bundle.sh <src_dir> <out_dir> -- run scan_pkg.sh from THIS bundle's layout.
#
# scan_pkg.sh assumes a flat directory where the 6 producer .sc scripts and
# portable-engine-full-review-package/ are direct siblings (the original
# /home/claude/work layout). This wrapper assembles that flat layout in a temp
# dir from the bundle's actual structure and runs the ORIGINAL scan_pkg.sh
# unmodified, per SCAN_PKG_NOT_SELF_CONTAINED.md's recommended method.
#
# Validated 2026-08-24: scan_pkg_bundle.sh fixtures/mal-fixture <out> produced
# raw/*.tsv identical (sorted) to the bundled fixtures/mal-out/raw/, and
# gate_malicious_npm.py passed 13/13 against the fresh output.
#
# Requires JOERN_HOME (or Joern at /home/claude/work/joern-cli, scan_pkg.sh's
# hardcoded default).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE="$(dirname "$HERE")"
SRC="$(cd "$1" && pwd)"
OUT="$(mkdir -p "$2" && cd "$2" && pwd)"

FLAT="$(mktemp -d)"
trap 'rm -rf "$FLAT"' EXIT
cp "$HERE/scan_pkg.sh" "$FLAT/"
for n in guard loop denylist mal globalmut serialize; do
  cp "$BUNDLE/tchecker-property-adjudicator/producers/export_${n}_facts.sc" "$FLAT/"
done
ln -s "$BUNDLE/portable-engine-full-review-package" "$FLAT/portable-engine-full-review-package"
cd "$FLAT" && bash scan_pkg.sh "$SRC" "$OUT"
