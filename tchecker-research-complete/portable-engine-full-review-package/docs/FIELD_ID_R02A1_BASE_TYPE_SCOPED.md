# FIELD-ID-R02a.1 — BASE-TYPE-SCOPED MEMBER RESOLUTION. Identity emission only. SHIPPED.
# Resolves an ambiguous member name WITHIN the base identifier's struct type, not by global
# name. No capacity consumption, no reader/bound change, no alias inference, no Tor names.

## TYPE CHAIN (verified present in exports, not assumed)
  base identifier ->  type_full_name ('create_cell_t*')
  strip ptr/const/struct  ->  'create_cell_t'
  type_decls table: name -> type_decl_id(s)  (a struct name may map to several duplicate
                    type_decls across headers/TUs; Joern shares the MEMBER decl id across them)
  members table: (type_decl_id, member_name) -> member decl (id + type_full_name)
So base->member resolves as: member decl whose declaring type_decl is (any type_decl named
<stripped base type>). SOUND uniqueness: all duplicate type_decls of that struct name must
AGREE on the member decl id + type, else abstain.

## RULE (structural, per spec)
  member GLOBAL-unique?          -> use it (R02a path, resolved_via=GLOBAL_UNIQUE)
  member name ambiguous (>1)?    -> scope by base type:
        strip base type_full_name -> struct name -> its type_decl_ids -> member in THAT type
        unique + agreeing -> resolve (resolved_via=BASE_TYPE_SCOPED)
        else -> abstain (UNRESOLVED)
  base not a simple identifier (arr[i]/call/nested) -> AMBIGUOUS_BASE (abstain)

## COMPILED TEETH (typefidtest.c) — ALL PASS
  struct A{char reply[16]; char unique_a[8];}; struct B{char reply[64];}; typedef A A_t;
  TYPE-FID-1 a->reply -> A::reply (decl 98784247808)        PASS
  TYPE-FID-2 b->reply -> B::reply (decl 98784247810)        PASS
  TYPE-FID-3 A::reply != B::reply (distinct decls, same spelling)  PASS
  TYPE-FID-4 a->unique_a resolves                            PASS
  Typedef: td(A_t *a){a->reply} resolves to A::reply (A_t's members share A's decl ids) PASS
No name-based shortcut: distinctness comes from the declaring type_decl, not the spelling.

## MAIN YIELD EXPERIMENT — Tor onion.c (the 94 re-measured)
  BEFORE (R02a): FIELD_IDENTITY_COMPLETE 13; 94 name-ambiguous abstained.
  AFTER  (R02a.1):
    FIELD_IDENTITY_COMPLETE:   100
      GLOBAL_UNIQUE:            13   (R02a baseline)
      RECOVERED_BY_BASE_TYPE:   87   <- the yield: 87 of 94 ambiguous names disambiguated
                                        by real base-type evidence
    STILL UNRESOLVED:           57   (base type not establishable, or duplicate type_decls
                                      disagree -> sound abstain)
    AMBIGUOUS_BASE:             36   (arr[i]/nested base -> abstain, correct)
DEFENSIBLE RESULT: of the 94 previously name-ambiguous accesses, 87 become uniquely
resolvable using actual base-type evidence. (Not targeting the old unsound 107.)

## ZERO VERDICT MOVEMENT — CONFIRMED (mandatory)
  tcpdump OOB_WRITE 11, OOB_COMPARE 0; raft OOB_WRITE 8;
  canonical 31/31 EXECUTED, REGRESSIONS 0 (49 PASS/0 FAIL); engine-core 7ad2880e04e84fd5 UNCHANGED.
Identity emission only; no consumer wired; inert on verdicts.

## KEPT SEPARATE (not touched in R02a.1)
- Member type dimension loss (onionskin exports 'uint8_t[]' not 'uint8_t[505]'): a
  capacity/type-shape concern for R02b, NOT identity. Identity answers "which field", not
  "how large". Untouched.
- Capacity consumption of the identity: R02b.
- Interprocedural caller-guard (create_cell_init:110): TOR-B3, still unsolved (correct).
- Typedef resolved here only because Joern shares member decl ids across the typedef's
  type_decl; no typedef resolver was invented. Cases it can't resolve stay UNRESOLVED.

## create_cell_init:110 PROGRESSION
  after R02a:    field id YES (onionskin globally unique), dest cap unchanged
  after R02a.1:  field id YES for the 87 recovered ambiguous members too; dest cap STILL
                 unchanged (no consumer) — as required.

## STATUS
Shipped R02a.1 (normalizer 9c535347e330c483). Base-type-scoped member resolution; 4/4 type
teeth; 87/94 Tor ambiguous names recovered (13->100 complete); ZERO verdict movement;
canonical 31/31; engine-core UNCHANGED. Next: R02b (wire capacity consumption to the frozen
field identity; candidate surface may legitimately move; adjudicate every new candidate).
