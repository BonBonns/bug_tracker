#!/usr/bin/env python3
"""OOB-INTERPROC-R01 gate. Validates oob_interprocedural_verdict.py -- the first
slice of step 6 (cross-function capacity propagation), single-hop, bare-argument
only. Covers: propagation flags an unguarded write through a propagated-capacity
parameter; a sizeof-guard on that parameter still suppresses; propagation is
DROPPED (not guessed) when two call sites disagree on the capacity; propagation
does NOT happen through a non-bare argument (`obj->field`); propagation does NOT
happen through a non-EXACT-resolved call."""
import sys, pathlib, importlib.util
H = pathlib.Path(__file__).resolve().parent
TOOLS = H.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("oip", TOOLS / "oob_interprocedural_verdict.py")
oip = importlib.util.module_from_spec(spec); spec.loader.exec_module(oip)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

c = oip.emit_candidates(str(H / "fixtures" / "controls.program.json"))
by_fn = {x['function_id']: x for x in c}

ck("exactly 1 candidate (only helper_unbounded's propagated write)", len(c) == 1)

ck("helper_unbounded FLAGGED via single-hop propagation from caller_single's buf[16]",
   950000000002 in by_fn and by_fn[950000000002]['dest'] == 'dest'
   and by_fn[950000000002]['elem_count'] == 16)

ck("helper_conflict ABSTAINED (caller_conflict_a proposes 8, caller_conflict_b "
   "proposes 32 for the same parameter -- dropped, not guessed)",
   950000000005 not in by_fn)

ck("helper_field ABSTAINED (caller_field_arg passes obj->field, not a bare "
   "identifier -- no propagation)",
   950000000007 not in by_fn)

ck("helper_guarded suppressed (n > sizeof(dest) credited even though capacity "
   "came from propagation, not a local)",
   950000000009 not in by_fn)

ck("helper_unresolved_target ABSTAINED (the call's resolution is UNRESOLVED, not "
   "EXACT -- no propagation through an unresolved call target)",
   950000000011 not in by_fn)

print(f"OOB_INTERPROC_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
