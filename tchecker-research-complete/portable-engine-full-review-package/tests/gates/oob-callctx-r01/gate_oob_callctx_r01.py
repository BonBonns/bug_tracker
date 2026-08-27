#!/usr/bin/env python3
"""OOB-CALLCTX-R01 gate. Validates call_context_guard.py's CallContextGuardFact
propagation (consumed by oob_runtime_capacity_verdict.py) against the full
requested control table:

  Runtime guard dominates call                -> Guard credited (suppressed)
  Assertion dominates call                     -> Not credited (remains)
  Guard occurs after call                      -> Not credited (remains)
  Guard exists only on one incoming branch     -> Ambiguous (remains)
  One guarded and one unguarded call site      -> Unguarded context remains
  Arguments in different names/positions       -> Formal mapping required (works)
  Signed/unsigned conversion changes meaning   -> Unresolved without range proof

Each control uses its OWN callee function, so candidates are independently
attributable (test 5 deliberately shares one callee across two callers to test
the "don't merge call sites" rule specifically)."""
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
by_fn = {}
for x in c:
    by_fn.setdefault(x['function_id'], []).append(x)

callee = {
    'guard_dominates': 991010000001, 'assert_only': 991020000001, 'guard_after_call': 991030000001,
    'conditional_branch': 991040000001, 'shared_callee': 991050000001, 'index_mapping': 991060000001,
    'signedness_mismatch': 991070000001,
}

ck("guard_dominates SUPPRESSED (real runtime guard, dominates the single call site)",
   callee['guard_dominates'] not in by_fn)

ck("assert_only NOT suppressed (assertion dominates the call, but assertions "
   "never count as enforcement)",
   callee['assert_only'] in by_fn)

ck("guard_after_call NOT suppressed (the guard executes AFTER the call -- "
   "irrelevant to it)",
   callee['guard_after_call'] in by_fn)

ck("conditional_branch NOT suppressed (guard exists on only ONE incoming branch "
   "to the call -- AMBIGUOUS, not confidently credited)",
   callee['conditional_branch'] in by_fn)

ck("shared_callee NOT suppressed (one caller guards its call site, the other "
   "does not -- per-call-site evidence is never merged; the unguarded context "
   "keeps the candidate live)",
   callee['shared_callee'] in by_fn)

ck("index_mapping SUPPRESSED (caller and callee use COMPLETELY DIFFERENT variable "
   "names -- limit/source/qty vs bound/srcVar/n -- credited only because the "
   "actual-to-formal mapping is strictly INDEX-based, not name-matching)",
   callee['index_mapping'] not in by_fn)

ck("signedness_mismatch NOT suppressed (the guard's own two compared operands "
   "have different signedness -- int vs unsigned int -- a C usual-arithmetic-"
   "conversion could change the predicate's real meaning; UNRESOLVED without a "
   "range proof this module doesn't attempt)",
   callee['signedness_mismatch'] in by_fn)

print(f"OOB_CALLCTX_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
