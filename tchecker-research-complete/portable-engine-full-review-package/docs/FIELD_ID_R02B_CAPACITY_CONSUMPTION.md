# FIELD-ID-R02b — FIELD IDENTITY -> CAPACITY CONSUMPTION. Measured + teeth-proven. NOT SHIPPED.
# Wires capacity extraction to consume the frozen FieldStorageIdentity. Design sound; blocked
# from shipping by (1) a guard that pins the old resolution code shape, and (2) the primary
# finding: Tor's array dimension is universally lost (uint8_t[]), so capacity yield is ZERO on Tor.

## CAP-FID TEETH (capfidtest.c) — ALL PASS
Capacity from member_decl_id -> declared type -> fixed array T[N] (NOT from composite key).
  CAP-FID-1 a->reply = 16                                    PASS
  CAP-FID-2 b->reply = 64                                    PASS
  CAP-FID-3 same spelling, NO capacity crossover (16!=64)    PASS
  CAP-FID-4 c->fixed = 32                                    PASS
  CAP-FID-5 c->dynamic = UNKNOWN (pointer member abstains)   PASS
  x->a=16, x->b=64 (no borrowing between members)            PASS
Capacity flows through field identity correctly and keeps identity != capacity.

## TOR onion.c CAPACITY-CONSUMPTION CLASSIFICATION (the R02b yield measurement)
  FIELD_ID_PRESENT:          10
  MEMBER_DECL_PRESENT:       10
  CAPACITY_EMITTED:           0   <- ZERO capacity unlocked on Tor
  POINTER_MEMBER:             0
  UNKNOWN_ARRAY_DIMENSION:   10   <- ALL 10 are uint8_t[] (dimension lost by frontend)
The six previously-blocked sites (create_cell_init:110 cell_out->onionskin, created_cell_parse
:209/:218 cell_out->reply, create_cell_from_create2:278, extend..:319 node_id, extended_cell_
parse:435) ALL classify as TYPE_DIMENSION_LOST: field identity YES, member decl YES, member
type uint8_t[] -> no dimension -> no capacity. The uint8_t[] loss is NOT isolated to onionskin;
it is UNIVERSAL across onion.c struct-array members. This is the load-bearing finding.

## TWO BLOCKERS TO SHIPPING R02b (both honest)
1. GUARD COUPLING (why canonical failed). GUARD-R01's capacity control asserts the SOURCE TEXT
   contains the exact line "_cap=_fixed_array_capacity(_mem.get('type_full_name') or '')" (the
   B2a.1 name-based resolution). R02b routes capacity through field identity
   (_memdecl_by_id[...].type_full_name), so that exact line is gone -> CAPACITY_CONTROLS 9/10 ->
   GUARD-R01 FAIL -> REGRESSIONS 1. The guard is a code-shape/provenance assertion; R02b
   legitimately changes the shape. Updating the guard to assert the NEW invariant (still
   fixed-array-only via _fixed_array_capacity, still single-level, pointers abstain) is a
   GUARD change -> OUT OF R02b scope ("no new BoundFact/guard logic"). Not done silently.
2. CANDIDATE MOVEMENT (adjudicated). With the &-normalization fix (operand &obj.member vs
   fieldAccess obj.member), R02b's identity path resolves capacity for MORE tcpdump sites than
   the B2a.1 name path: tcpdump 11 -> 13. Set-diff:
     + handle_beacon:1416 memcpy dest_cap=8B
     + handle_probe_response:1583 memcpy dest_cap=8B
   BOTH ADJUDICATED SAFE: memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN) where
   timestamp[IEEE802_11_TSTAMP_LEN=8] -> extent is a CONSTANT == capacity. Safe (CONSTANT_EXTENT
   shape), but not suppressed because STATIC_EXTENT_SAFE only fires for literal sizeof(dest), not
   a named constant == cap. 0 real bugs; +2 safe FPs. This IS legitimate R02b movement, but it
   moves the frozen tcpdump anchor 11->13, which needs conscious acceptance, not silent landing.

## REGRESSION CAUGHT (the process working)
Shipping R02b: canonical GUARD-R01 FAIL, REGRESSIONS 1. REVERTED to R02a.1 (9c535347e330c483).
Frozen state restored: tcpdump 11, raft 8, canonical 31/31, engine-core 7ad2880e04e84fd5.
NOTE also caught a HIDDEN regression pre-fix: without the &-normalization, R02b's identity path
matched NOTHING on tcpdump (0 struct-member caps, parse_elements:1214 lost its capacity+bound
entirely) yet tcpdump still read 11 -- a capability regression MASKED by an identical count. The
set-diff/behavioral check (not the count) caught it. This is exactly why "11->11 is not
self-evidently safe."

## DECISION: R02b design PROVEN, NOT SHIPPED. Next = ARRAY-DIM-R01 (as preregistered)
The R02b capacity-consumption design is correct (teeth pass; identity->decl->type->extent;
pointer abstains; no crossover). But on Tor it unlocks ZERO capacity because the array
DIMENSION is universally lost (uint8_t[]). Per the milestone: do NOT patch around the
dimension loss inside R02b, and do NOT infer 505 from MAX_CREATE_LEN or source text. Make it
the next characterization:

  ARRAY-DIM-R01 — recover struct-member fixed-array DIMENSION
    Question: is the [N] recoverable from ANY existing exported type fact (type_decls,
    a sized-type table, the CPG's typeFullName elsewhere) rather than the members table's
    stripped 'uint8_t[]'? Characterize before implementing. If not recoverable from evidence,
    the honest state is: Tor struct-member capacity is blocked at the frontend type export.

Also required before a future R02b ship: consciously update GUARD-R01's capacity control to
assert the NEW resolution invariant (fixed-array-only via _fixed_array_capacity, single-level,
pointer/non-array abstain) instead of the exact B2a.1 line -- as its own reviewed change.

## STATUS
NOT SHIPPED. Engine frozen at R02a.1 (9c535347e330c483), engine-core 7ad2880e04e84fd5 UNCHANGED,
tcpdump 11, raft 8, canonical 31/31. R02b design + CAP-FID teeth PROVEN. Tor capacity yield = 0
(dimension loss). Reference patch saved (/tmp/b2b/normalize_r02b.py). Next: ARRAY-DIM-R01
characterization of the uint8_t[] dimension loss; and a conscious GUARD-R01 update when R02b
is later shipped.
