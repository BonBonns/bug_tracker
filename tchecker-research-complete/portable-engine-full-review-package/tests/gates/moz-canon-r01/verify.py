#!/usr/bin/env python3
"""Assertions for MOZ-CANON-R01 -- see run.sh's header comment for the full
rationale. Uses oob_cursor_write_verdict.py (the current, frozen cursor-write
producer) as the reference implementation -- this gate exists to canonically pin
down what that producer says about ONE real, disclosed CVE, not to re-derive the
producer's own logic."""
import sys, pathlib
TOOLS = pathlib.Path(__file__).resolve().parent.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import oob_cursor_write_verdict as ocw

vuln_path, patched_path = sys.argv[1], sys.argv[2]
vuln = ocw.emit_candidates(vuln_path)
patched = ocw.emit_candidates(patched_path)

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)


def the_candidate(cands):
    return [c for c in cands if c.get('base') == '_buffer' and c.get('pointer') == 'buffer'
            and c.get('file') == 'jchuff.c']


vuln_hits, patched_hits = the_candidate(vuln), the_candidate(patched)

ck(f"exact security-relevant candidate present in VULNERABLE revision ({len(vuln_hits)} site(s))",
   len(vuln_hits) > 0)
ck("VULNERABLE revision capacity recorded as 136 (BUFSIZE=(DCTSIZE2*2)+8)",
   bool(vuln_hits) and all(c['elem_count'] == 136 for c in vuln_hits))

ck(f"same candidate STILL present in PATCHED revision ({len(patched_hits)} site(s)) -- "
   "NOT suppressed, CORRECTLY: the real fix is a capacity-constant increase, not a "
   "missing guard, so a syntactic pass has no way to prove 256 is 'enough' where 136 "
   "wasn't -- see the module docstring and moz-scan-paired-cve-validation-round1.md",
   len(patched_hits) > 0)
ck("PATCHED revision capacity recorded as 256 (BUFSIZE=(DCTSIZE2*4)) -- the capacity "
   "DELTA is the evidence a human reviewer actually needs, faithfully recorded",
   bool(patched_hits) and all(c['elem_count'] == 256 for c in patched_hits))

ck("same NUMBER of sites for this candidate in both revisions (structural shape "
   "unchanged by the fix, only the recorded capacity differs)",
   len(vuln_hits) == len(patched_hits) and len(vuln_hits) > 0)


def structural_shape(cands):
    # "Unrelated candidates remain unchanged": compare the FULL candidate set (not
    # just the one under test) by (function-relative line, write shape, base array)
    # -- proving nothing else in the output shifted incidentally.
    return sorted((c['line'] - (c.get('function_line') or 0), c['write_shape'], c['base'])
                  for c in cands)


vshape, pshape = structural_shape(vuln), structural_shape(patched)
ck(f"ALL candidates structurally unchanged between revisions ({len(vuln)} total each "
   "side, same per-function relative-line + write-shape + base-array set)",
   len(vuln) == len(patched) and vshape == pshape and len(vuln) > 0)

print("\nEvidence recorded for human review:")
for label, hits in (("VULNERABLE", vuln_hits), ("PATCHED", patched_hits)):
    if hits:
        c = hits[0]
        print(f"  {label}: function={c['function']} array={c['base']} pointer={c['pointer']} "
              f"capacity={c['elem_count']} bytes  write_shape={c['write_shape']}  "
              f"({len(hits)} site(s), first @L{c['line']})")

print(f"\nMOZ_CANON_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
