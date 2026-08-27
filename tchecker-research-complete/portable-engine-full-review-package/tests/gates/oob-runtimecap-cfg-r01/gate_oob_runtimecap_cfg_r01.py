#!/usr/bin/env python3
"""OOB-RUNTIMECAP-CFG-R01 gate. Validates the CFG-sensitive, per-sink free
invalidation in allocation_extent.py (capacity_status_at_sink), replacing the
earlier whole-function invalidation that was shown (round 11) to cost real
coverage on NSS CVE-2019-17006. Covers the full control table:

  allocate -> write -> free                          : ESTABLISHED
  allocate -> free -> write                           : INVALID (not flagged)
  allocate -> error branch (free + return) -> write   : ESTABLISHED
  allocate -> conditional free -> joined write        : AMBIGUOUS (not flagged)
  misleading id/line order (free's id < write's id,
    but write executes first in the CFG)              : ESTABLISHED, determined
                                                         from the graph, not id order

Realloc-replaces-prior-capacity is already covered by tests/gates/oob-runtimecap-r01
(vuln_realloc_replaces) and unaffected by this change -- not re-tested here."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
TOOLS = H.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("orc", TOOLS / "oob_runtime_capacity_verdict.py")
orc = importlib.util.module_from_spec(spec); spec.loader.exec_module(orc)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = orc.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 3 candidates (the three ESTABLISHED functions -- write-then-free, "
   "error-branch-free-return, misleading-order; the INVALID and AMBIGUOUS ones "
   "correctly excluded)",
   len(c) == 3)

ck("established_write_then_free FLAGGED (the free comes AFTER this write in the "
   "CFG -- ESTABLISHED at this sink)",
   980000000001 in by_fn)

ck("invalid_free_then_write NOT flagged (free dominates the write AND alloc "
   "dominates the free -- guaranteed freed before this write -- INVALID)",
   980000000002 not in by_fn)

ck("established_error_branch_free_return FLAGGED (the free is on an error "
   "branch that RETURNS before reaching the write -- irrelevant to this sink)",
   980000000003 in by_fn)

ck("ambiguous_conditional_free_joined_write NOT flagged (a conditional free "
   "rejoins before the write -- AMBIGUOUS, not confidently usable)",
   980000000004 not in by_fn)

ck("established_misleading_goto_order FLAGGED (free's call id/line is "
   "deliberately numbered AFTER the write's, but that is irrelevant either way -- "
   "the CFG says write executes strictly BEFORE free; determined from cfg_edges, "
   "never from id/line ordering)",
   980000000005 in by_fn)

print(f"OOB_RUNTIMECAP_CFG_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
