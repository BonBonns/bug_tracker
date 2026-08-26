# FIELD-ID-R02a — STRUCT-FIELD STORAGE IDENTITY, EMISSION ONLY. SHIPPED.
# Emits FieldStorageIdentity=(base_storage_id, member_decl_id) as a standalone auditable
# fact. NO consumer wired. REQUIRED: zero verdict movement. Achieved.

## REPRESENTATION (provenance explicit, per spec)
For an eligible field access, emit to .fieldidentity.json:
  storage_kind    = FIELD
  base_storage_id = <base identifier's unique ref_target>
  member_decl_id  = <unique member declaration id>
  composite_key   = FIELD:<base_storage_id>:<member_decl_id>   (deterministic, auditable)
  member_name, member_type, code, derivation(rule=CPP_FIELD_STORAGE_IDENTITY)
Both original components retained; composite key derived, not opaque.

## ELIGIBILITY (narrow, abstain otherwise)
  base:   direct IDENTIFIER with exactly ONE resolved ref_target
  member: FIELD_IDENTIFIER whose name resolves to exactly ONE member declaration
Abstain -> AMBIGUOUS_BASE (arr[i].a, get_obj()->a, nested base) or UNRESOLVED.

## COMPILED TEETH (fieldidtest.c) — ALL 8 PASS
  FID-1 x->a != x->b        PASS  (same base, different member decl)
  FID-2 x->a != y->a        PASS  (same member, different base storage)
  FID-3 x->b != y->a        PASS
  FID-4 z->a != x->a        PASS  (z has base storage 94489280512 != x's 111669149696;
                                   NO auto-unify; would require alias machinery on z vs x)
  FID-5 p->fixed identity resolves     PASS
  FID-6 p->dynamic identity resolves   PASS
  FID-7 p->dynamic capacity UNKNOWN    PASS  (type char*, not fixed array)
  FID-8 arr[i].a AMBIGUOUS_BASE        PASS  (base is indexAccess, no fabricated identity)

## ZERO VERDICT MOVEMENT (the R02a requirement) — CONFIRMED
  tcpdump OOB_WRITE   11 (unchanged)
  tcpdump OOB_COMPARE  0 (unchanged)
  raft   OOB_WRITE     8 (unchanged)
  canonical            31/31 EXECUTED, REGRESSIONS 0 (49 PASS / 0 FAIL)
  engine-core          7ad2880e04e84fd5 UNCHANGED
Identity emission touches no capacity/bound/verdict path. Confirmed inert.

## TOR onion.c MEASUREMENT — with HONEST RECONCILIATION of the preregistered 107
Preregistered (from FIELD-ID-R01): 107 recoverable. ACTUAL R02a impl: 13. RECONCILED:
  loose probe (FIELD-ID-R01 method):     107   <- counted member name present in members
  strict impl (member UNIQUE per spec):   13
  abstained: ambiguous member name (>1 struct): 94   (e.g. 'reply' exists in 2 structs)
  abstained: base not a simple identifier:      36
The FIELD-ID-R01 "107" was an OVERCOUNT: my characterization probe matched member NAME
without enforcing "member resolves to exactly ONE declaration." The R02a implementation
correctly enforces uniqueness (the spec's mandate), so it abstains on the 94 field accesses
whose member name appears in >1 struct. This is the SAME "same spelling != same storage"
discipline: a member name shared across structs is ambiguous by name alone. 13 is the SOUND
count; 107 was unsound. The record is corrected: FIELD-ID-R01's yield estimate was too high
because the probe was looser than the shipped, spec-compliant check.

## KNOWN LIMITATION (design refinement, NOT in R02a scope)
The member is currently resolved by GLOBAL name-uniqueness. The base's TYPE is known
(cell_out : create_cell_t*), so an access could be disambiguated by resolving the member
WITHIN the base struct type (type_decl), recovering many of the 94. This is a real, sound
refinement (base-type-scoped member resolution) but is a SEPARATE step (FIELD-ID-R02a.1),
NOT bundled here. Also: onion.c's member types export as 'uint8_t[]' (dimension lost by the
frontend) — a capacity concern for R02b, not identity.

## create_cell_init:110 PROGRESSION (as preregistered)
  before FIELD-ID:  role YES, extent YES, field id NO,  dest cap NO
  after  R02a:      role YES, extent YES, field id YES, dest cap unchanged (no consumer)
Identity now present for cell_out->onionskin (onionskin is a UNIQUE member name -> resolves:
FIELD:<storage(cell_out)>:<decl(onionskin)>). Capacity still NO — correctly, since R02a
wires no consumer. R02b would connect capacity.

## STATUS
Shipped R02a (normalizer cbefdfb4b2c43dd5). Identity-only emission; 8/8 teeth; zero verdict
movement; canonical 31/31; engine-core 7ad2880e04e84fd5 UNCHANGED. Honest correction: sound
Tor yield is 13 (unique-member), not the 107 loose-probe estimate. Next: R02a.1 (base-type-
scoped member resolution, recover ambiguous-name members) OR R02b (wire capacity consumption
to the new identity) — each measured separately, per staged plan.
