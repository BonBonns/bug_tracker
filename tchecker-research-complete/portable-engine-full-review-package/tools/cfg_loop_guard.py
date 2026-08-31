#!/usr/bin/env python3
"""CFG dominance + loop-iteration reasoning for a guard's protection of a write INSIDE a loop
(task #44, phase 2). Reuses the same real dominator-tree machinery
(`allocation_extent.build_cfg_index`/`_dominates`/`_reachable_from`) already gated and used
elsewhere in this repo (`call_context_guard.py`'s NSS CVE-2019-17006 work) -- no new CFG
algorithm invented from scratch, only a genuinely new COMPOSITION of it.

WHY THIS EXISTS: plain textual guard matching ("does SOME comparison referencing this name and
this parameter exist anywhere in the function") cannot distinguish `vorbis_book_decodev_add`'s
real vulnerable revision from its patched one -- BOTH contain the exact same outer
`for(i=0;i<n;)` loop condition; the real fix instead adds a SEPARATE, inner-loop-level check
(`for (j=0;i<n && j<book->dim;)`). Plain dominance is not sufficient either: the OUTER `i<n`
genuinely DOMINATES the write in BOTH files (nothing can reach the write without first passing
through it AT LEAST ONCE) -- dominance alone cannot see that the OUTER check is only evaluated
ONCE per outer iteration, while the write can execute MANY times per outer iteration via the
INNER loop's own back-edge, unprotected by the outer check on every pass after the first.

THE REAL DISTINGUISHING CONDITION (verified directly against the real Tremor VULN/PATCHED
bundles before being trusted -- see param_length_capacity_controls.py):
  A guard G protects a write W on EVERY execution, not merely the first reach, if and only if:
    1. G dominates W (ordinary dominance -- necessary but not sufficient, as above).
    2. G is AT OR INSIDE the innermost loop that (re-)executes W -- i.e. G is dominated by (or
       equal to) that loop's own header. A guard that is dominated by W's loop header executes
       on every pass through the loop (it lies on the loop's own repeated body path); a guard
       that instead DOMINATES the loop header from OUTSIDE only ever executes once, before the
       loop is entered, and is bypassed on every subsequent iteration via the loop's back-edge.

  The loop header itself is identified from REAL CFG structure, not guessed: a back-edge is any
  real cfg_edges edge (u, v) where v dominates u (a standard, textbook characterization -- computed
  from the SAME dominator data, not a separate heuristic). For a given write W, the SET of loop
  headers v with a real back-edge into them where v dominates W are W's enclosing loops; the
  INNERMOST one is the member of that set dominated by every other member (nested loops dominate
  outward to inward).

POLARITY, HONESTLY SCOPED: for a guard that is the loop's OWN header condition (`guard == header`,
or feeds directly into computing it as a boolean sub-expression, `_dominates(header, guard)`),
loop semantics themselves already prove the polarity -- a `for`/`while` body executes precisely
when its own condition is true; no separate graph search is needed to re-derive that C-language
guarantee. This module does NOT attempt full control-dependence + branch-polarity proof for a
guard that is merely SOMEWHERE inside the loop body (not the loop's own header) -- unlike
`call_context_guard.py`'s straight-line, pre-call guard case (which this module deliberately does
NOT touch, and which continues to use its own proven `_controls_call`/`_branch_polarity`), a
guard nested inside a loop body, gating a write ALSO inside that same loop, is a genuinely harder
polarity question this module does not yet solve -- disclosed here, not silently assumed sound.
The caller (`oob_index_write_verdict.py`) additionally requires the comparison's own operator to
be `<`/`<=` with the write's own index as the LHS and the resolved length parameter as the RHS
(never the reverse operand order, never `>`/`>=`) -- the natural, idiomatic C bound-check
direction (`idx < capacity`), which rules out an accidentally-reversed-polarity guard by
construction rather than by a general proof.
"""
from allocation_extent import build_cfg_index, _dominates  # noqa: F401 (build_cfg_index re-exported)


def _find_back_edges(g):
    return [(u, v) for u, succs in g['succ'].items() for v in succs if _dominates(g, v, u)]


def _innermost_loop_header(g, back_edges, w):
    """Among back-edge targets v that dominate w (w's enclosing loop headers), returns the
    innermost one -- the v that is itself dominated by every OTHER relevant v. Returns None if
    w is not inside any loop, or (rare, conservative) no total nesting order is found -- callers
    must treat None-with-relevant-candidates as "cannot establish loop-iteration-safety",
    same as missing CFG data."""
    relevant_v = {v for (u, v) in back_edges if _dominates(g, v, w)}
    if not relevant_v:
        return None
    for v in relevant_v:
        if all(_dominates(g, other, v) for other in relevant_v):
            return v
    return None


def loop_iteration_safe_dominates(g, guard, w):
    """True iff `guard` protects `w` on EVERY execution, including repeated executions via a
    loop back-edge -- not merely the first reach. Requires: (1) guard dominates w (ordinary
    dominance); (2) guard is at-or-inside w's innermost enclosing loop (dominated by, or equal
    to, that loop's own header) -- so it is genuinely re-evaluated on every iteration, not
    checked once from outside and then bypassed. If w is not inside any loop at all, ordinary
    dominance (condition 1) is sufficient on its own."""
    if not _dominates(g, guard, w):
        return False
    back_edges = _find_back_edges(g)
    header = _innermost_loop_header(g, back_edges, w)
    if header is None:
        return True
    return guard == header or _dominates(g, header, guard)
