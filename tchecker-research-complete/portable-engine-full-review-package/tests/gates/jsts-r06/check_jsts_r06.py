#!/usr/bin/env python3
"""JSTS-R06: replay the real-Joern Gates 3-23 fixtures through the ACTUAL Java core
(loader -> PortableProvenanceEngine) and grade with an explicit per-function ledger.

Statuses (per the review feedback — one aggregate number hides too much):
  PASS                  engine matches the expected semantics with current vocabulary
  EXPECTED_UNSUPPORTED  semantics require State/Identity/Capture vocabulary the
                        ProgramGraph does not have yet; engine must ABSTAIN
                        (no proven positions), never fabricate
  FRONTEND_GAP          frontend/export lacks the fact needed even for abstention
  NORMALIZER_GAP        normalization dropped/never produced a needed record
  LOADER_REJECTED       loader threw (validation) — listed verbatim
  ENGINE_MISMATCH       vocabulary sufficient but engine result wrong  <- real bug

Expectations below are hand-curated per function from the original gate ground
truths, restricted to what phase-1 vocabulary (calls/args/returns/locals/
single-def assignments) can legitimately express.
"""
import json, re, subprocess, sys
from pathlib import Path

# ROOT is derived from THIS FILE's location — a hardcoded absolute path here
# silently graded a STALE build directory from an earlier session (found while
# promoting closureTwoCaptures: the harness reported UNRESOLVED while the same
# command run by hand reported AMBIGUOUS).
ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'tests/gates/jsts-r05/build'   # reuse compiled loader+engine+runner
import os
REPLAY = Path(os.environ.get('REPLAY_DIR', '/tmp/replay'))

# fn -> ('EXPECT', resolution, proven_positions)   engine must match
# fn -> ('UNSUP',)                                  engine must ABSTAIN (proven == [])
EXPECTATIONS = {
    # g03 (JS call resolution era): process(x){return x}; exact() flows through it.
    # ambiguous/unknown call shapes must abstain in phase-1 vocabulary.
    'g03': {'process': ('EXPECT', 'EXACT', [0]),
            'exact': ('EXPECT', 'EXACT', [0]),
            'ambiguous': ('UNSUP',), 'unknown': ('UNSUP',)},
    # g04 typed dispatch: typed/untyped resolve to the single concrete A.process
    # (untyped via the measured weak-receiver rule); union/missing must abstain.
    # g04 verified from source: A.process returns x; B.process returns "CONST".
    # typed/untyped -> single concrete A.process, input is caller param 1.
    # unionTyped: AMBIGUOUS over {A,B}.process -> common dep only as MAY [1].
    'g04': {'process': ('EXPECT', 'EXACT', [0]),
            'typed': ('EXPECT', 'EXACT', [1]),
            'untyped': ('EXPECT', 'EXACT', [1]),
            # FRONTEND_GAP CLOSED via the tsc union sidecar (tsc_union_types.js):
            # the TypeScript CHECKER recovers the declared 'A | B' that jssrc2cpg
            # destroys in every exportable channel (declared=ANY, arg=A:<init>,
            # candidates=A-only, dynamicTypeHints=A-only — all measured). The
            # normalizer overrides the declared receiver from the sidecar; the
            # classifier expands the union to existing member methods, AMBIGUOUS,
            # never EXACT. Engine: input possible via A.process, not proven
            # (B.process returns a constant). The old FGAP flip-assertion fired
            # exactly as armed and forced this reclassification.
            'unionTyped': ('EXPECT', 'AMBIGUOUS', [], [1]),
            'missing': ('UNSUP',)},
    # runExact chains through getWorker(h) (returns new A()): receiver is an opaque
    # allocation return -> phase-1 abstention is correct until state/identity land.
    'g07': {'runExact': ('EXPECT', 'EXACT', [1]),
            'runAmbiguous': ('UNSUP',), 'runUnknown': ('UNSUP',)},
    'g08': {'runExact': ('EXPECT', 'EXACT', [1]),
            'runAmbiguous': ('UNSUP',), 'topAmbiguous': ('UNSUP',)},
    # g09-g13 property/state/alias semantics: not in phase-1 vocabulary -> abstain
    'g09': {'directState': ('UNSUP',), 'topState': ('UNSUP',)},
    # sameObject flipped as an UNPREDICTED side-effect of S02; verified against the
    # gate10 prototype truth (origins=['PARAM:sameObject.source']) before accepting:
    # single-allocation must identity through setValue/readValue is exactly S02
    # vocabulary. differentField truth is STATE_UNKNOWN -> abstention stays correct.
    'g10': {'sameObject': ('EXPECT', 'EXACT', [0]), 'differentField': ('UNSUP',)},
    'g12': {'aliasSame': ('UNSUP',), 'aliasOverwrite': ('UNSUP',)},
    # CORE-S02: identity-keyed interprocedural state -> alias rows EXPECT (were UNSUP)
    # STATUS-R03 migration: identical evidence (proven=[], may=[1], unknown=true);
    # only the expected LABEL moves, because may-non-empty + unknown now means
    # POSSIBLE_UNBOUNDED rather than AMBIGUOUS.
    'g13': {'mayAliasWrite': ('EXPECT', 'POSSIBLE_UNBOUNDED', [], [1]),
            'sameAliasBothBranches': ('EXPECT', 'EXACT', [1]),
            'mayAliasOverwrite': ('EXPECT', 'AMBIGUOUS', [], [1]),
            'mayAliasRead': ('EXPECT', 'AMBIGUOUS', [], [1])},
    # g15-g17: pure identity/constant flows ARE expressible; state/may flows abstain.
    'g15': {'mayAliasWrite': ('EXPECT', 'POSSIBLE_UNBOUNDED', [], [1]),
            'mayAliasRead': ('EXPECT', 'AMBIGUOUS', [], [1])},
    'g16': {'identity': ('EXPECT', 'EXACT', [0]),
            'mayAliasOverwrite': ('UNSUP',)},
    'g17': {'identity': ('EXPECT', 'EXACT', [0]),
            'mayAliasOverwrite': ('UNSUP',)},
    # g20-g23 indexed/destructuring/spread/closures: abstain in phase 1
    # CORE-S01: keyed state is vocabulary-supported -> these EXPECT (were UNSUP)
    'g20': {'objectStaticExact': ('EXPECT', 'EXACT', [1]),
            'objectDynamicWrite': ('EXPECT', 'AMBIGUOUS', [], [2])},
    'g21': {'objectDestructureExact': ('UNSUP',), 'arrayRest': ('UNSUP',)},
    # SPREAD DERIVATION landed (tmp-collapse via block membership + per-slot
    # expansion + dynamic-pollution transfer + array push offsets); validated
    # 10/10 against the full gate22 prototype truth. Rows flip.
    'g22': {'objectSpreadExact': ('EXPECT', 'EXACT', [1]),
            'objectSpreadDynamicWrite': ('EXPECT', 'AMBIGUOUS', [], [2])},
    # CORE-S03: capture chains + scope-narrowed lambda dispatch (JSTS-R07 promoted)
    # + multi-def MAY locals -> closure rows EXPECT (were UNSUP)
    # CPP-R03 item 2 (expression decomposition) x CORE-S03 (capture chains):
    # the long-recorded closureTwoCaptures limit is CLOSED — `() => a + b` over
    # two captured params resolves MAY over both, never EXACT.
    'g23': {'closureDirect': ('EXPECT', 'EXACT', [0]),
            'closureMutation': ('EXPECT', 'AMBIGUOUS', [], [0]),
            'closureTwoCaptures': ('EXPECT', 'AMBIGUOUS', [], [0, 1])},
}


def run_engine(pf):
    args = ['java', '-cp', str(BUILD), 'EndToEndRunner', str(pf)]
    st = pf.parent / 'state_facts.json'
    idf = pf.parent / 'identity_facts.json'
    cap = pf.parent / 'capture_facts.json'
    if st.exists():
        args.append(str(st))
        if idf.exists():
            args.append(str(idf))
            if cap.exists():
                args.append(str(cap))
                expr = pf.parent / (pf.name + '.expression.json')
                if expr.exists():
                    args.append(str(expr))
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr

def parse_summaries(out):
    m = {}
    for line in out.splitlines():
        mm = re.match(r'SUMMARY (\S+) resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+) completeness=(\S+)', line)
        if mm:
            pos = lambda s: [int(x) for x in s.split(',') if x.strip()]
            m.setdefault(mm.group(1), []).append({'res': mm.group(2), 'proven': pos(mm.group(3)),
                              'may': pos(mm.group(4)), 'unknown': mm.group(5) == 'true'})
    return m

ledger = []
def add(g, fn, status, detail=''):
    ledger.append((g, fn, status, detail))

for g in sorted(EXPECTATIONS):
    pf = REPLAY / g / 'program_facts.json'
    if not pf.exists():
        for fn in EXPECTATIONS[g]:
            add(g, fn, 'NORMALIZER_GAP', 'no program_facts.json')
        continue
    try:
        rc, out, err = run_engine(pf)
    except Exception as e:
        for fn in EXPECTATIONS[g]:
            add(g, fn, 'LOADER_REJECTED', str(e)[:80])
        continue
    if rc != 0 or 'ANALYSIS_STATUS=COMPLETE' not in out:
        msg = (err + out)[-160:].replace('\n', ' ')
        for fn in EXPECTATIONS[g]:
            add(g, fn, 'LOADER_REJECTED', msg)
        continue
    summaries = parse_summaries(out)
    for fn, exp in EXPECTATIONS[g].items():
        ss = summaries.get(fn)
        if not ss:
            add(g, fn, 'FRONTEND_GAP', 'function not in engine output')
            continue
        if exp[0] == 'EXPECT':
            res, proven = exp[1], exp[2]
            may = exp[3] if len(exp) > 3 else None
            hit = [x for x in ss if x['res'] == res and x['proven'] == proven and (may is None or x['may'] == may)]
            if hit:
                add(g, fn, 'PASS', f"{res} proven={proven}" + (f" may={may}" if may is not None else ''))
            else:
                add(g, fn, 'ENGINE_MISMATCH', f"expected ({res},{proven}{',' + str(may) if may is not None else ''}) got {[(x['res'], x['proven'], x['may']) for x in ss]}")
        elif exp[0] == 'FGAP':
            pf_doc = json.load(open(pf))
            rec = next((c for c in pf_doc['calls']
                        if c['enclosing_function_id'] in
                           [f['id'] for f in pf_doc['functions'] if f['name'] == fn]
                        and c.get('resolution_reason') not in (None, 'NOT_DISPATCH_CALL')), None)
            collapsed = rec is not None and (rec.get('receiver_declared_type') in ('ANY', '', None)) \
                        and not any(' | ' in t for t in rec.get('canonical_targets', []))
            if collapsed:
                add(g, fn, 'FRONTEND_GAP', exp[1] + ' (collapse still measured)')
            else:
                add(g, fn, 'ENGINE_MISMATCH', 'frontend now carries union info — reclassify this case')
            continue
        else:  # UNSUP: no summary may claim an EXACT hard path with proven positions
            fab = [x for x in ss if x['res'] == 'EXACT' and x['proven']]
            if not fab:
                d0 = ss[0]
                add(g, fn, 'EXPECTED_UNSUPPORTED', f"abstained/soft: {[(x['res'], x['proven'], x['may']) for x in ss]}")
            else:
                add(g, fn, 'ENGINE_MISMATCH', f"FABRICATED EXACT proven={fab[0]['proven']} without vocabulary")

print(f"{'fixture':6s} {'function':24s} {'status':22s} detail")
for g, fn, st, d in ledger:
    print(f"{g:6s} {fn:24s} {st:22s} {d}")
from collections import Counter
counts = Counter(st for _, _, st, _ in ledger)
print('\nledger totals:', dict(counts))
bad = counts.get('ENGINE_MISMATCH', 0) + counts.get('LOADER_REJECTED', 0)
print(f"JSTS_R06={'PASS' if bad == 0 else 'FAIL'} (mismatches+rejections={bad})")
sys.exit(0 if bad == 0 else 1)
