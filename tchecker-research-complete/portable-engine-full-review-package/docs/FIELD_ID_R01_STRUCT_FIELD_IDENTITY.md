# FIELD-ID-R01 — STRUCT-FIELD STORAGE IDENTITY. Measurement + design. NO implementation.
# Question: smallest neutral representation giving field-access memory operands stable
# identity when value_ref.id == -1. No capacity/bound/verdict/interproc/Tor changes.

## CENTRAL FINDING: the two pieces ALREADY EXIST in exported facts
A field access (a->x) is exported as an <operator>.indirectFieldAccess CALL with:
  arg idx 1 = BASE object   (IDENTIFIER 'a', carries ref_target = base storage id)
  arg idx 2 = MEMBER         (FIELD_IDENTIFIER 'x', name -> members.tsv decl id + type)
So FieldStorageIdentity = (base_storage_id, member_decl_id) is DERIVABLE from existing
exports. No synthetic identity from source spelling required.
  base_storage_id: identifiers.tsv last column (ref_target of the base identifier)
  member_decl_id:  members.tsv row id, looked up by the FIELD_IDENTIFIER name
  member_type:     members.tsv type_full_name (gives capacity for array members)

## TEETH FIXTURE (fieldidtest.c) — ALL DISTINCTIONS HOLD
  x->a = (stor 111669149696, decl 98784247808)  char[16]
  x->b = (stor 111669149696, decl 98784247809)  char[64]
  y->a = (stor 111669149697, decl 98784247808)  char[16]
  x->a != x->b   (same base, DIFFERENT member decl)         PASS
  x->a != y->a   (same member decl, DIFFERENT base storage) PASS
  x->b != y->a   (differ on both)                           PASS
Controls:
  z->a: base storage 94489280512 (DISTINCT from x's 111669149696). Does NOT auto-unify with
        x->a; unification would require alias machinery to prove z==x. NO name shortcut. PASS
  p->fixed  (char[32])  -> identity resolves AND capacity resolvable                     PASS
  p->dynamic(char*)     -> identity resolves BUT capacity stays UNKNOWN (pointer member)  PASS
  arr[i].a  -> base is an indexAccess (arr[i]), NOT a plain identifier -> AMBIGUOUS_BASE
               -> ABSTAIN. Does NOT collapse all arr[*].a into one storage object.        PASS
Every mandatory tooth passes on compiled code.

## TAXONOMY APPLIED TO onion.c (real Tor)
  BASE_PLUS_MEMBER_VISIBLE: 107   <- complete (base_storage, member_decl) identity available
  UNRESOLVED:                50       (no base identifier ref / no member decl -> abstain)
  AMBIGUOUS_BASE:            36       (arr[i].m / nested base -> abstain, correctly)
=> 107 onion.c field accesses would gain STABLE storage identity from EXISTING facts. This
resolves the FIELD_IDENTITY_GAP for the create_cell_init:110-class dests (cell_out->onionskin
= (storage(cell_out), decl(onionskin)), decl type uint8_t[MAX_CREATE_LEN]). The 6
capacity-lost-to-identity sites measured in TOR-B2c.0 are inside the 107.

## DESIGN (the smallest neutral representation — NOT YET IMPLEMENTED)
Add a neutral FieldStorageIdentity to a field-access memory operand when, and only when:
  - the base arg is an IDENTIFIER with a resolved ref_target (base_storage_id present), AND
  - the member FIELD_IDENTIFIER name resolves to exactly one member decl (member_decl_id).
Then the operand's storage key becomes the PAIR (base_storage_id, member_decl_id) instead of
the collapsed value_ref.id=-1. Capacity/bound readers would key on this pair. Abstain
(leave id=-1, no identity) for AMBIGUOUS_BASE (indexAccess/nested base) and UNRESOLVED.
INVARIANTS PRESERVED:
  - numeric/name equality never establishes identity: identity is the (base storage, member
    decl) PAIR from real refs, not the spelling 'buf'.
  - z->a unifies with x->a ONLY via existing alias machinery on the base (z vs x); this layer
    does not itself alias bases.
  - pointer members resolve IDENTITY but NOT capacity (type is not a fixed array).
  - array-of-struct element bases (arr[i]) abstain.

## WHY THIS BEFORE TOR-B3
TOR-B3 (caller-guard -> arg binding -> callee param -> sink) is a large interprocedural
semantic expansion. FIELD-ID-R01 is narrow, intraprocedural/frontend-local, Tor-agnostic,
and already causes 6 concrete capacity losses in one Tor file (107 recoverable identities
total). It benefits OOB_WRITE, OOB_READ, STATIC_EXTENT_SAFE, future compare-capacity, and
future interproc (all need to know what storage a field denotes). It is the higher-value,
lower-risk next build.

## MULTI-BLOCKER RECORD FOR create_cell_init:110 (preserved, informative)
  operation              REPRESENTED
  extent                 REPRESENTED
  field storage identity MISSING        <- FIELD-ID-R01 would supply this (in the 107)
  destination capacity   BLOCKED BY FIELD IDENTITY
  local guard            ABSENT BY DESIGN
  caller guard           EXISTS (parse_create2_payload: handshake_len > MAX_CREATE_LEN)
  interprocedural safety  UNMODELED     <- TOR-B3 (later)
Sequence: FIELD-ID-R01 (stable field identity -> capacity available) THEN later TOR-B3
(caller-guard interprocedural safety). Macro-capacity relation stays PARKED (not yet the
limiting factor).

## STATUS
Measurement + design only. NO code change. Both identity pieces confirmed present in exports;
teeth pass on compiled fixture; 107 onion.c field accesses recoverable. Engine-core
7ad2880e04e84fd5 UNCHANGED. Recommendation: FIELD-ID-R01 implementation is the next build,
keyed on (base_storage_id, member_decl_id), abstaining on ambiguous/unresolved bases.
