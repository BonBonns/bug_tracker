#!/usr/bin/env bash
# CPP-PERF-R01 -- permanent performance regression gate for the two O(n^2) hot spots
# fixed in normalize_c_cpp_facts_v03.py (commit 00f95c5), root-caused on real
# mozilla/mozjpeg jchuff.c. See gen_stress_fixture.py's docstring for how this
# fixture was validated (A/B tested against the pre-fix revision, not assumed).
#
# Asserts, on a from-scratch synthetic fixture (no mozjpeg source in this repo):
#   1. BOUNDED RUNTIME    -- each of two independent scans completes within
#                            $TIMEOUT_SECONDS wall-clock seconds.
#   2. NO WORKLIST-CAP HIT -- neither run's stderr contains the
#                            REACHDEF_WORKLIST_CAP_HIT marker the normalizer itself
#                            emits if a function's reaching-def fixpoint doesn't
#                            converge within its 200,000-pop cap.
#   3. DETERMINISTIC FACT COUNTS -- both runs produce the identical count for every
#                            top-level fact array (assignments, calls, locals, ...).
#   4. BYTE-IDENTICAL OUTPUT -- both runs' cpp.json are identical once the one known
#                            nondeterministic field (metadata[].root, an absolute
#                            work-directory path) is normalized out.
#
# Requires JOERN_HOME set to a valid joern-cli (same precondition as cpp-r06); this
# gate SKIPs (not FAILs) if Joern isn't available, consistent with the rest of the
# Layer-2 gates in run_everything.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PE="$(cd "$HERE/../../.." && pwd)"
TIMEOUT_SECONDS="${CPP_PERF_R01_TIMEOUT:-200}"
STRESS_N="${CPP_PERF_R01_N:-2000}"

if [ -z "${JOERN_HOME:-}" ] || [ ! -x "$JOERN_HOME/c2cpg.sh" ]; then
    echo "SKIP  CPP-PERF-R01 (JOERN_HOME not set to a valid joern-cli)"
    exit 0
fi
export C2CPG_HEAP="${C2CPG_HEAP:-3g}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src"
python3 "$HERE/gen_stress_fixture.py" "$STRESS_N" "$WORK/src/stress_test.c" || {
    echo "FAIL  CPP-PERF-R01 (fixture generation failed)"; exit 1; }

FAIL=0
for i in 1 2; do
    START=$(date +%s)
    timeout "$TIMEOUT_SECONDS" python3 "$PE/tools/scan_repo.py" --lang c --all-files \
        --out "$WORK/run$i/report.json" --work "$WORK/run$i/work" "$WORK/src" \
        > "$WORK/run$i.log" 2>&1
    RC=$?
    END=$(date +%s)
    ELAPSED=$((END - START))
    if [ $RC -eq 124 ]; then
        echo "FAIL  CPP-PERF-R01 run $i: exceeded ${TIMEOUT_SECONDS}s (unbounded runtime -- possible O(n^2) regression)"
        FAIL=1
    elif [ $RC -ne 0 ]; then
        echo "FAIL  CPP-PERF-R01 run $i: scan_repo.py exited $RC"
        tail -10 "$WORK/run$i.log" | sed 's/^/        /'
        FAIL=1
    else
        echo "  run $i: ${ELAPSED}s (bound: ${TIMEOUT_SECONDS}s)"
    fi
    if grep -q "REACHDEF_WORKLIST_CAP_HIT" "$WORK/run$i.log"; then
        echo "FAIL  CPP-PERF-R01 run $i: REACHDEF_WORKLIST_CAP_HIT fired (reaching-def fixpoint did not converge)"
        grep "REACHDEF_WORKLIST_CAP_HIT" "$WORK/run$i.log" | sed 's/^/        /'
        FAIL=1
    fi
done
[ $FAIL -eq 1 ] && exit 1

python3 - "$WORK/run1/work/cpp.json" "$WORK/run2/work/cpp.json" <<'PYEOF'
import json, sys
p1, p2 = sys.argv[1], sys.argv[2]
d1, d2 = json.load(open(p1)), json.load(open(p2))

def strip_nondet(d):
    d = dict(d)
    d['metadata'] = [{k: v for k, v in m.items() if k != 'root'} for m in d.get('metadata', [])]
    return d

ok = True
for key in sorted(set(d1) | set(d2)):
    n1 = len(d1.get(key, [])) if isinstance(d1.get(key), list) else None
    n2 = len(d2.get(key, [])) if isinstance(d2.get(key), list) else None
    if n1 is not None and n1 != n2:
        print(f"FAIL  CPP-PERF-R01: non-deterministic fact count for '{key}': run1={n1} run2={n2}")
        ok = False
if ok:
    print(f"  fact counts identical across both runs (assignments={len(d1.get('assignments', []))}, "
          f"calls={len(d1.get('calls', []))})")

s1, s2 = strip_nondet(d1), strip_nondet(d2)
if json.dumps(s1, sort_keys=True) != json.dumps(s2, sort_keys=True):
    print("FAIL  CPP-PERF-R01: cpp.json differs between runs after normalizing metadata.root")
    ok = False
else:
    print("  cpp.json byte-identical across both runs (after normalizing metadata.root)")
sys.exit(0 if ok else 1)
PYEOF
PYRC=$?
[ $PYRC -ne 0 ] && FAIL=1

if [ $FAIL -eq 0 ]; then
    echo "PASS  CPP-PERF-R01 (bounded runtime, no worklist-cap hit, deterministic, byte-identical)  CPP_PERF_R01=4/4"
else
    echo "CPP_PERF_R01=0/4"
fi
exit $FAIL
