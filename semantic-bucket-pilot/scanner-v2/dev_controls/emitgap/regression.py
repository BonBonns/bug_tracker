#!/usr/bin/env python3
"""Regression on the CONSUMED corpus (development evidence only).

Replays the frozen diagnosis cache (276 cached function-packet CPGs, one per
labeled write site) and measures the emission gap that the form-aware fix closes:
a recognized memcpy-family sink whose destination is NON-BARE was silently DROPPED
by the old `analyze_operations` (bare-only). It now emits an explicit, form-aware
abstention/candidate. This is a DEVELOPMENT measurement on consumed data -- it is
regression evidence only; any recognition claim needs a NEW held-out corpus.

Soundness invariants asserted here:
  * every previously-dropped non-bare site now emits a record (no silent drop);
  * NONE is promoted to a safe verdict (`deterministic_complete`) -- the heap
    producer never finalizes a non-heap destination as safe;
  * each record's reason is one of the form-aware causal codes -- UPDATED for the
    V1/V2 delegation split: a fixed-extent destination (array or scalar) now
    reports `delegated_to_stack_capacity_v2` (a REROUTED handoff) instead of the
    old, misleading `capacity_relation_not_established` for BOTH the literal-fits
    and literal-exceeds sub-cases (V1 no longer computes that comparison at all --
    see oob_runtime_capacity_verdict.diagnose_nonbare_destination). `analysis_status
    == 'rerouted'` is therefore also an expected, non-drop outcome here, distinct
    from `deterministic_complete` (still asserted to never occur for a non-bare
    destination) and from `abstained`/`open_candidate`.
"""
import glob, json, os, re, sys, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
SV = os.path.join(HERE, "..", "..")
TOOLS = os.path.join(SV, "..", "..", "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)
CACHE = os.path.join(SV, "study", "heldout_diagnosis", "cache")


def _L(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(TOOLS, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


P = _L("oob_runtime_capacity_verdict")
from callee_contracts import CALLEE_CONTRACTS

BARE = re.compile(r'[A-Za-z_]\w*')

# Join cache packets (filename == site_id[:16]) to the frozen diagnosis labels so
# the LABELED-site delta can be reported separately from the body-wide delta.
DIAG = os.path.join(SV, "study", "heldout_diagnosis", "raw_diagnosis.jsonl")
LABEL = {}
if os.path.exists(DIAG):
    for line in open(DIAG):
        r = json.loads(line)
        LABEL[r['site_id'][:16]] = r


def nonbare_memcpy_sites(d):
    """Recognized memcpy-family sinks (contract-matched) whose destination is
    NON-BARE -- exactly the operations the OLD producer silently dropped."""
    out = []
    for c in d.get('calls', []):
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        dest = (args[da].get('code') or '').strip()
        if dest and not re.fullmatch(BARE, dest):
            out.append((c.get('enclosing_function_id'), dest, c.get('line')))
    return out


REASON_OK = {'destination_identity_ambiguous', 'required_evidence_absent',
             'capacity_relation_not_established', 'delegated_to_stack_capacity_v2'}

dropped_old = 0            # non-bare recognized memcpy sites, body-wide (old = drop)
emitted_new = 0            # now producing a record
by_reason = {}
by_form = {}
safe_promotions = 0        # deterministic_complete at a non-bare site (must be 0)
files_with_gap = 0

# LABELED-site delta: the packet's own labeled vulnerable write, when it is the
# non-bare recognized memcpy (this is the "group-A" made visible).
lab_vuln_nonbare = 0
lab_vuln_emitted = 0
lab_reason = {}

for cpp in sorted(glob.glob(os.path.join(CACHE, "*.cpp.json"))):
    try:
        d = json.load(open(cpp))
    except Exception:
        continue
    sid16 = os.path.basename(cpp).split('.')[0]
    lab = LABEL.get(sid16)
    sites = nonbare_memcpy_sites(d)
    recs = P.analyze_operations(cpp)
    rec_by_key = {(r.get('dest'), r.get('line')): r for r in recs}

    if sites:
        files_with_gap += 1
        dropped_old += len(sites)
        for (fn, dest, line) in sites:
            r = rec_by_key.get((dest, line))
            if r is None:
                continue    # form-aware fix emits for every non-bare site
            emitted_new += 1
            rc = r.get('reason_code')
            by_reason[rc] = by_reason.get(rc, 0) + 1
            by_form[r.get('destination_form')] = by_form.get(r.get('destination_form'), 0) + 1
            if r.get('analysis_status') == 'deterministic_complete':
                safe_promotions += 1

    # labeled-site delta (vulnerable, copy_sink, non-bare labeled dest)
    if lab and lab.get('is_vulnerable') and lab.get('label_class') == 'destination_write' \
            and lab.get('write_kind') == 'copy_sink':
        ldest = (lab.get('write_dest') or '').strip()
        if ldest and not re.fullmatch(BARE, ldest):
            lab_vuln_nonbare += 1
            # match any emitted record whose dest equals the labeled dest
            hit = next((r for r in recs if r.get('dest') == ldest), None)
            if hit is not None:
                lab_vuln_emitted += 1
                lab_reason[hit.get('reason_code')] = lab_reason.get(hit.get('reason_code'), 0) + 1

TOT = len(glob.glob(os.path.join(CACHE, '*.cpp.json')))
print(f"cached function packets scanned : {TOT}")
print("--- BODY-WIDE (every non-bare recognized memcpy in the packets) ---")
print(f"packets with a non-bare memcpy  : {files_with_gap}")
print(f"non-bare recognized sites (old=silently DROPPED) : {dropped_old}")
print(f"now emitting a visible record   : {emitted_new}")
print(f"still silently dropped          : {dropped_old - emitted_new}")
print(f"safe promotions at these sites  : {safe_promotions}  (MUST be 0)")
print("by reason_code:")
for k, v in sorted(by_reason.items(), key=lambda kv: -kv[1]):
    print(f"   {v:3}  {k}")
print("by destination_form:")
for k, v in sorted(by_form.items(), key=lambda kv: -kv[1]):
    print(f"   {v:3}  {k}")
print("--- LABELED VULNERABLE non-bare copy_sink sites (group-A subset) ---")
print(f"labeled vuln non-bare copy_sink : {lab_vuln_nonbare}")
print(f"now emitting at the labeled dest: {lab_vuln_emitted}")
print("labeled-site reason_code:")
for k, v in sorted(lab_reason.items(), key=lambda kv: -kv[1]):
    print(f"   {v:3}  {k}")

ok = (emitted_new == dropped_old and safe_promotions == 0
      and set(by_reason) <= REASON_OK and set(lab_reason) <= REASON_OK)
print("\nREGRESSION PASS" if ok else "\nREGRESSION FAIL")
sys.exit(0 if ok else 1)
