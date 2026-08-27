#!/usr/bin/env python3
"""Generates a SYNTHETIC C stress fixture reproducing the COMPOUND-R02 "prior
contribution" O(n^2) hot spot that drove normalize_c_cpp_facts_v03.py to run
unboundedly on real mozilla/mozjpeg jchuff.c (commit
a06aeb25f2c5bc986d46301113df2eaf2a3c055c^, see
moz-scan-paired-cve-validation-round1.md). Neither jchuff.c nor any mozjpeg source is
copied here (licensing/bloat -- same policy as the rest of this repo's paired-CVE
work); this is a from-scratch, mechanically-generated stand-in for the SHAPE of the
problem (many compound-assignment operators -- `+=`, `^=`, etc. -- targeting the SAME
local variable within one function, as jchuff.c's PUT_BITS/EMIT_BYTE bit-packing
macros do when expanded), not a reproduction of the file.

VALIDATED, not assumed: this exact shape was A/B tested against the pre-fix and
post-fix normalizer (temporarily swapping in the parent-of-00f95c5 revision, then
restoring the fix) before being adopted as the permanent gate's fixture. At N=2000:
  - post-fix (current):  ~139s wall time, completes normally.
  - pre-fix (reverted):  did NOT complete within a 280s timeout (>2x slower, still
    running) -- confirming this fixture actually exercises the fixed hot path, not
    just "some C file that happens to be slow to parse." An earlier if/else-branch-
    heavy fixture design was tried FIRST and discarded after the same A/B test showed
    NO gap (57-140s either way) -- it didn't use real compound-assignment operators,
    so it never touched the COMPOUND-R02 code path at all. Left as a cautionary note:
    a stress fixture that "looks" pathological isn't a valid regression gate until
    it's proven to actually regress without the fix.

Does NOT attempt to reproduce the OTHER fixed hot spot (the reaching-def worklist's
dense-CFG revisit cost, gated separately by scanning for the
REACHDEF_WORKLIST_CAP_HIT stderr marker the normalizer itself emits if any function's
fixpoint doesn't converge within its 200,000-pop cap) -- that one needs actual
unresolved/aliased pointer writes to trigger (CPP_UNMODELLED_POINTER_WRITE), which is
harder to synthesize reliably and is instead covered passively: this gate's own run
would surface that marker too if it ever fired, even though this fixture wasn't
designed to specifically provoke it.
"""
import sys

STRESS_N = 2000  # same-target compound-assignment statements; validated above


def generate(n=STRESS_N):
    lines = [
        "int stress_compound_chain(int seed) {",
        "    unsigned int x = seed;",
    ]
    ops = ['^=', '+=', '-=', '|=']
    for k in range(n):
        lines.append(f"    x {ops[k % len(ops)]} {k % 251};")
    lines += [
        "    return (int)x;",
        "}",
        "",
    ]
    return "\n".join(lines)


if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else STRESS_N
    out = sys.argv[2] if len(sys.argv) > 2 else None
    src = generate(n)
    if out:
        with open(out, 'w') as f:
            f.write(src)
        print(f"wrote {out} ({len(src.splitlines())} lines, N={n})")
    else:
        print(src)
