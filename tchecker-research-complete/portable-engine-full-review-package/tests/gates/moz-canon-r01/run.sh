#!/usr/bin/env bash
# MOZ-CANON-R01 -- canonical vulnerable-versus-patched gate for the real mozjpeg
# jchuff.c Huffman-encoder buffer-overrun CVE (Debian bug 768369, fixed upstream at
# mozilla/mozjpeg@a06aeb25f2c5bc986d46301113df2eaf2a3c055c). See
# moz-scan-paired-cve-validation-round1.md for the full history.
#
# Fetches the two real commits FRESH via a shallow, SHA-pinned git fetch --
# jchuff.c and its headers are NOT copied into this repo (licensing/bloat, same
# policy as the rest of this repo's paired-CVE work). Requires JOERN_HOME and
# network access to github.com; SKIPs (not FAILs) if either is unavailable, same
# posture as the other Layer-2 gates.
#
# Asserts (see verify.py for the actual checks):
#   1. The exact security-relevant candidate (array _buffer, pointer buffer, in
#      jchuff.c's encode_one_block functions) is present in the VULNERABLE revision
#      with capacity=136 (BUFSIZE=(DCTSIZE2*2)+8).
#   2. The SAME candidate is STILL present in the PATCHED revision, now with
#      capacity=256 (BUFSIZE=(DCTSIZE2*4)) -- NOT suppressed. This is the CORRECT
#      result for this specific CVE, not a detector gap: the real fix was a
#      capacity-constant increase, not a missing guard, so a syntactic pass has no
#      way to prove 256 is "enough" where 136 wasn't -- that needs modeling the
#      Huffman encoder's actual worst-case bit-output math, out of scope by design.
#      What this gate proves instead is that the capacity DELTA is faithfully
#      recorded as evidence, which is the honest, correct value this pass can add.
#   3. Every OTHER candidate in the same scan is structurally unchanged between
#      revisions (same count, same per-function relative line positions) -- the
#      fix's effect on this pass's output is isolated to the recorded capacity,
#      nothing else shifted incidentally.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PE="$(cd "$HERE/../../.." && pwd)"

if [ -z "${JOERN_HOME:-}" ] || [ ! -x "$JOERN_HOME/c2cpg.sh" ]; then
    echo "SKIP  MOZ-CANON-R01 (JOERN_HOME not set to a valid joern-cli)"
    exit 0
fi
export C2CPG_HEAP="${C2CPG_HEAP:-3g}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PATCHED_SHA="a06aeb25f2c5bc986d46301113df2eaf2a3c055c"

mkdir -p "$WORK/gitcache"
( cd "$WORK/gitcache" && git init -q \
  && git remote add origin https://github.com/mozilla/mozjpeg.git \
  && git fetch --depth 2 origin "$PATCHED_SHA" ) > "$WORK/fetch.log" 2>&1
if [ $? -ne 0 ]; then
    echo "SKIP  MOZ-CANON-R01 (could not fetch mozilla/mozjpeg -- no network access?)"
    sed 's/^/        /' "$WORK/fetch.log"
    exit 0
fi

HEADERS="jdct.h jerror.h jinclude.h jmorecfg.h jpeglib.h"
for rev in vuln patched; do
    mkdir -p "$WORK/$rev/src"
    REF="$PATCHED_SHA"; [ "$rev" = "vuln" ] && REF="${PATCHED_SHA}^"
    ( cd "$WORK/gitcache" && git show "$REF:jchuff.c" ) > "$WORK/$rev/src/jchuff.c" 2>/dev/null
    if [ ! -s "$WORK/$rev/src/jchuff.c" ]; then
        echo "FAIL  MOZ-CANON-R01: could not extract jchuff.c at $REF"
        exit 1
    fi
    for h in $HEADERS; do
        ( cd "$WORK/gitcache" && git show "$REF:$h" ) > "$WORK/$rev/src/$h" 2>/dev/null
    done
    : > "$WORK/$rev/src/jconfig.h"   # not checked in at this revision; empty stub is
                                     # sufficient for parsing (same as this session's
                                     # earlier manual paired-CVE staging).
    python3 "$PE/tools/scan_repo.py" --lang c --all-files \
        --out "$WORK/$rev/scan/report.json" --work "$WORK/$rev/scan/work" "$WORK/$rev/src" \
        > "$WORK/$rev.scan.log" 2>&1
    if [ $? -ne 0 ]; then
        echo "FAIL  MOZ-CANON-R01: scan of $rev revision failed"
        tail -15 "$WORK/$rev.scan.log" | sed 's/^/        /'
        exit 1
    fi
done

python3 "$HERE/verify.py" "$WORK/vuln/scan/work/cpp.json" "$WORK/patched/scan/work/cpp.json"
RC=$?
if [ $RC -eq 0 ]; then
    echo "PASS  MOZ-CANON-R01"
else
    echo "FAIL  MOZ-CANON-R01"
fi
exit $RC
