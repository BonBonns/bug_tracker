#!/usr/bin/env python3
"""Before/after delta across repo scans: abstentions, new EXACT, new MAY,
unchanged unresolved, and — the safety check — any HARDENED result
(a claim that got stronger in a way that drops uncertainty)."""
import json, sys

def load(p):
    d = json.load(open(p))
    out = {}
    for side in d['sides']:
        for r in side['rows']:
            out[(side['label'], r['function'])] = r
    return out

def cls(r):
    """Classify by CLAIM, not just by positions. 'EXACT with no origins' is a
    POSITIVE claim ("analysis complete; nothing flows here"), NOT an abstention —
    conflating the two is what hid the corrected rows in this tool's first
    version."""
    if r is None: return 'ABSENT'
    if r['proven']: return 'EXACT' if r['resolution'] == 'EXACT' else 'PROVEN_NONEXACT'
    if r['may']: return 'MAY'
    if r['resolution'] == 'EXACT' and not r['unknown'] and r['completeness'] == 'COMPLETE':
        return 'CLAIMED_NO_ORIGIN'
    return 'UNRESOLVED'

total = {'before_abstained': 0, 'after_abstained': 0, 'new_exact': 0, 'new_may': 0,
         'unchanged_unresolved': 0, 'hardened': 0, 'weakened': 0, 'corrected_false_complete': 0,
         'new_claimed_no_origin': 0}
hardened_rows = []
corrected_rows = []
claimed_rows = []
for name, before_p, after_p in [tuple(x.split('=')) for x in sys.argv[1:]]:
    b, a = load(before_p), load(after_p)
    keys = sorted(set(b) | set(a))
    row = {'new_exact': 0, 'new_may': 0, 'unchanged_unresolved': 0, 'hardened': 0, 'weakened': 0,
           'corrected_false_complete': 0, 'new_claimed_no_origin': 0}
    ba = sum(1 for k in b if 'abstention' in b[k]); aa = sum(1 for k in a if 'abstention' in a[k])
    for k in keys:
        cb, ca = cls(b.get(k)), cls(a.get(k))
        if cb == ca == 'UNRESOLVED': row['unchanged_unresolved'] += 1
        if cb == 'UNRESOLVED' and ca == 'EXACT': row['new_exact'] += 1
        if cb == 'UNRESOLVED' and ca == 'MAY': row['new_may'] += 1
        # HARDENING = a result that gained proven positions or lost uncertainty
        # without new *proof* — i.e. MAY -> EXACT, or unknown flag dropped while
        # positions grew. Any occurrence is a red flag to investigate.
        if cb == 'MAY' and ca == 'EXACT':
            row['hardened'] += 1; hardened_rows.append((name, k, 'MAY->EXACT'))
        if b.get(k) and a.get(k):
            if set(b[k]['proven']) - set(a[k]['proven']) == set() and set(a[k]['proven']) - set(b[k]['proven']):
                if not a[k]['unknown'] and b[k]['unknown']:
                    row['hardened'] += 1; hardened_rows.append((name, k, 'gained proven + dropped unknown'))
        if cb == 'EXACT' and ca == 'MAY': row['weakened'] += 1
        # A row that claimed EXACT/COMPLETE and now abstains is a CORRECTED FALSE
        # COMPLETE — the old claim asserted "no origins, analysis complete" while
        # silently dropping a contribution. Losing it is a soundness WIN, and the
        # first version of this tool had no bucket for it (blind spot, fixed).
        # The RISKIEST direction: an abstention becoming a positive "nothing flows
        # here" claim. Every such row must be verified against source — this is the
        # exact shape that was FALSE in the utf8 false-COMPLETE defect.
        if cb == 'UNRESOLVED' and ca == 'CLAIMED_NO_ORIGIN':
            row['new_claimed_no_origin'] += 1
            claimed_rows.append((name, k))
        if cb == 'CLAIMED_NO_ORIGIN' and ca in ('UNRESOLVED', 'MAY'):
            row['corrected_false_complete'] += 1
            corrected_rows.append((name, k))
    print(f"{name:12s} abstained {ba:3d} -> {aa:3d}   new_EXACT={row['new_exact']:2d} "
          f"new_MAY={row['new_may']:2d} unchanged_unresolved={row['unchanged_unresolved']:3d} "
          f"weakened(EXACT->MAY)={row['weakened']:2d} HARDENED={row['hardened']}")
    total['before_abstained'] += ba; total['after_abstained'] += aa
    for k2 in row: total[k2] = total.get(k2, 0) + row[k2]
print()
print('TOTAL', {k: v for k, v in total.items()})
if hardened_rows:
    print('HARDENED ROWS (must be investigated):')
    for r in hardened_rows: print('  ', r)
else:
    print('HARDENED ROWS: none')
if claimed_rows:
    print('NEW "NO ORIGIN" CLAIMS (verify each against source):')
    for r in claimed_rows: print('  ', r)
if corrected_rows:
    print('CORRECTED FALSE-COMPLETE ROWS (soundness wins):')
    for r in corrected_rows: print('  ', r)
