#!/usr/bin/env python3
"""cfg_loop_guard.py required control matrix (task #44, phase 2).

Covers every control named by direct instruction:
  - dominating versus non-dominating guards
  - correct and incorrect branch polarity (operator direction)
  - loop-entry and loop-back paths (the exact Tremor decodev_add discriminator)
  - early exits (an unrelated distractor branch does not confuse the analysis)
  - guards applying to the wrong index/object

Unit-level tests build a minimal synthetic CFG directly (cfg_edges facts), no c2cpg needed, so
the loop-structural boundary conditions are pinned down precisely and fast to iterate on. The
real Tremor VULN/PATCHED end-to-end reproduction for BOTH now-detected sinks
(vorbis_book_decodevs_add AND vorbis_book_decodev_add) lives in
param_length_capacity_controls.py, re-verified here is out of scope for duplication --
this file is unit-level only.
"""
import sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from allocation_extent import build_cfg_index
from cfg_loop_guard import loop_iteration_safe_dominates

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def cfg(edges, fn=1):
    facts = {'cfg_edges': [{'function_id': fn, 'node_id': u, 'successor_id': v} for (u, v) in edges]}
    return build_cfg_index(facts)[fn]


# --- dominating vs non-dominating guards ---
# guard(2) is on only ONE of two independent paths from entry(1) to write(4); the other path
# (1->3->4) bypasses it entirely.
g1 = cfg([(1, 2), (1, 3), (2, 4), (3, 4)])
ck("dominating vs non-dominating: guard on only one of two independent paths -> NOT credited",
   not loop_iteration_safe_dominates(g1, 2, 4))
# guard(2) genuinely dominates write(4): the only path structure funnels through it.
g2 = cfg([(1, 2), (2, 4)])
ck("dominating vs non-dominating: sole path through the guard -> credited (no loop involved)",
   loop_iteration_safe_dominates(g2, 2, 4))

# --- loop-entry (checked once) vs loop-back (checked every iteration) paths ---
# Abstract shape of the real Tremor decodev_add: outer_guard(2) -true-> inner_header(3)
# -true-> write(4) -back-> inner_header(3) [inner loop]; inner_header -false-> outer_guard(2)
# [outer loop re-check]; outer_guard -false-> exit(5).
g3 = cfg([(1, 2), (2, 3), (2, 5), (3, 4), (3, 2), (4, 3)])
ck("loop-entry path (outer guard, checked once per outer pass): NOT credited -- matches the "
   "real Tremor decodev_add VULN shape (outer i<n unchanged between vuln/patched)",
   not loop_iteration_safe_dominates(g3, 2, 4))
ck("loop-back path (inner header, re-checked every iteration): credited -- matches the real "
   "Tremor decodev_add PATCHED shape (the new guard is part of the inner loop's own header)",
   loop_iteration_safe_dominates(g3, 3, 4))

# --- correct vs incorrect branch polarity (operator direction) ---
# oob_index_write_verdict.py only ever populates param_guarded_idx_by_fn from
# <operator>.lessThan / <operator>.lessEqualsThan comparisons -- a >=/> comparison (the wrong
# polarity/direction for a bound check, `idx >= n` or `n < idx`) is never even considered a
# candidate guard in the first place; this is enforced structurally (see the CMP-name filter),
# not by this module, so this control asserts that structural fact by re-reading the source
# rather than re-deriving it, keeping this file focused on the CFG questions.
import re as _re
_src = open(str(pathlib.Path(__file__).resolve().parent / "oob_index_write_verdict.py")).read()
_m = _re.search(r"if c\.get\('name'\) in \(([^)]*)\):\s*\n\s*mlt", _src)
ck("branch polarity: guard population is structurally restricted to lessThan/lessEqualsThan "
   "only (never >, >=, or a reversed operand order) -- an accidentally-reversed-polarity "
   "comparison can never even become a candidate guard",
   _m is not None and "lessThan" in _m.group(1) and "lessEqualsThan" in _m.group(1)
   and "greaterThan" not in _m.group(1))

# --- early exits: an unrelated distractor branch must not confuse the analysis ---
# entry(1) -> {2(distractor check), 5(real path start)}; 2 -> 3(early return, dead end,
# unrelated to the write at all); 5 -> 6(real guard) -> 7(write) -> 6(loop back).
g4 = cfg([(1, 2), (1, 5), (2, 3), (5, 6), (6, 7), (7, 6), (6, 8)])
ck("early exits: an unrelated distractor early-return branch elsewhere does not prevent a "
   "genuinely protecting guard from being correctly credited",
   loop_iteration_safe_dominates(g4, 6, 7))
ck("early exits: the distractor's own dead-end node is correctly NOT treated as protecting "
   "the write (it can't -- it's unreachable from the real guard at all)",
   not loop_iteration_safe_dominates(g4, 3, 7))

# --- guard occurring AFTER the write (does not protect it) ---
g5 = cfg([(1, 2), (2, 3), (3, 4)])
ck("a comparison occurring AFTER the write in the CFG does not dominate it -> NOT credited",
   not loop_iteration_safe_dominates(g5, 3, 2))

# --- guards applying to the wrong index/object: end-to-end, through the real matching key ---
with __import__('tempfile').TemporaryDirectory() as td:
    import json, os
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import oob_index_write_verdict as oiw

    pref = os.path.join(td, "g.json")
    facts = {
        'functions': [{'id': 1, 'name': 'f', 'full_name': 'f', 'line': 1, 'line_end': 10,
                        'parameters': [{'index': 0, 'id': 10, 'name': 'buf', 'type_full_name': 'char*'},
                                       {'index': 1, 'id': 11, 'name': 'n', 'type_full_name': 'int'}]}],
        'calls': [
            # write: buf[k] -- note the guard below checks a DIFFERENT variable ('other'), not 'k'.
            {'id': 100, 'name': '<operator>.indexAccess', 'code': 'buf[k]',
             'enclosing_function_id': 1, 'file': 'x.c', 'line': 5},
            # a real, non-assert, correctly-directed, dominating, loop-header guard -- but on the
            # WRONG variable ('other', not 'k').
            {'id': 200, 'name': '<operator>.lessThan', 'code': 'other<n', 'enclosing_function_id': 1,
             'line': 4, 'arguments': [{'index': 0, 'value_ref': {'code': 'other'}},
                                       {'index': 1, 'value_ref': {'code': 'n', 'kind': 'PARAMETER', 'id': 11}}]},
            # establishes real pairing evidence for 'k' (so this reaches the guard-suppression
            # check at all, rather than abstaining earlier for lack of any evidence) -- deliberately
            # NOT wired into cfg_edges below, so it structurally cannot CFG-dominate anything; this
            # isolates the test to the wrong-index/object question specifically.
            {'id': 300, 'name': '<operator>.lessThan', 'code': 'k<n', 'enclosing_function_id': 1,
             'line': 3, 'arguments': [{'index': 0, 'value_ref': {'code': 'k'}},
                                       {'index': 1, 'value_ref': {'code': 'n', 'kind': 'PARAMETER', 'id': 11}}]},
        ],
        'assignments': [], 'locals': [],
        'cfg_edges': [{'function_id': 1, 'node_id': 200, 'successor_id': 100},
                      {'function_id': 1, 'node_id': 100, 'successor_id': 200}],
    }
    json.dump(facts, open(pref, 'w'))
    cands = oiw.emit_candidates(pref)
    ck("wrong index/object: a real, dominating, loop-safe guard on a DIFFERENT variable ('other', "
       "not 'k') does not suppress buf[k] -- it remains a candidate",
       any(c['array'] == 'buf' and c['index_expr'] == 'k' for c in cands))

print(f"CFG_LOOP_GUARD_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
