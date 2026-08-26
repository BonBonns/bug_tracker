# CONST-EXPR-R01 — compile-time constant export characterization.
# MAJOR CORRECTION: overturns ARRAY-DIM-R01's "dimension not exported" conclusion.

## HEADLINE FINDING (corrects prior milestones)
Joern's c2cpg DOES constant-fold object-like macros — including NESTED macros and
ARITHMETIC — into member typeFullName, WHEN the macro is actually defined at parse time.
Proven on a self-contained file with Tor's real macro chain:
  #define CELL_PAYLOAD_SIZE 509
  #define MAX_CREATE_LEN (CELL_PAYLOAD_SIZE - 4)
  uint8_t onionskin[MAX_CREATE_LEN];   ->  type_full = 'uint8_t[505]'   RESOLVED
  uint8_t viab[B], B=(A-4), A=32       ->  type_full = 'uint8_t[28]'    RESOLVED
So MAX_CREATE_LEN -> 505 folds correctly. The value IS in typeFullName.

## ROOT CAUSE OF THE EARLIER "uint8_t[]" (my error, not a frontend gap)
The /tmp/tor_onion scan built onion.c FLAT — copied the .c plus a few headers without the
real #include chain resolved. So at parse time MAX_CREATE_LEN / MAX_CREATED_LEN / DIGEST_LEN
were UNDEFINED, and the array dimension collapsed to uint8_t[]. This was a BROKEN SCAN
SETUP (missing include paths), NOT a Joern/frontend limitation and NOT a fundamental
dimension-export gap. ARRAY-DIM-R01's conclusion ("SYMBOLIC_DIMENSION_VISIBLE_VALUE_MISSING /
frontend can't export the value") is WITHDRAWN: with includes resolved, the value is
present in typeFullName as a folded literal.

## CONST-EXPR CLASSIFICATION (measured, corrected)
  literal [16]                         -> char[16]     RESOLVED_VALUE_VISIBLE
  object macro [A=32]                  -> char[32]     RESOLVED_VALUE_VISIBLE
  macro arithmetic [B=(A-4)=28]        -> uint8_t[28]  RESOLVED_VALUE_VISIBLE
  nested macro+arith [MAX_CREATE_LEN]  -> uint8_t[505] RESOLVED_VALUE_VISIBLE
  raw literal arithmetic [(32-4)]      -> char[(32-4)] CONST_EXPR_TREE (NOT folded; no macro)
  enum [C=64]                          -> char[C]      SYMBOL_NAME_VISIBLE (enum NOT folded)
So the ONLY genuinely-unresolved forms are (a) enum constants and (b) raw literal arithmetic
written directly in the declarator (rare). Object-like macros — the Tor case — fully resolve.

## IMPLICATION FOR THE WHOLE BRANCH
The blocker was never field identity, array-declarator visibility, OR const-expr export. It
was a SCAN HYGIENE bug: onion.c must be built with its include paths so macros resolve.
Consequences to re-examine (next milestone, not now):
  - R02b on a PROPERLY-BUILT Tor onion.c may actually yield capacity (onionskin -> 505),
    because typeFullName now carries uint8_t[505] and the EXISTING _fixed_array_capacity
    parses 'uint8_t[505]' directly — NO new const-expr layer needed.
  - The "6 capacity-blocked sites" / "0 CAPACITY_EMITTED on Tor" result was an ARTIFACT of
    the flat scan, not a real capability gap.

## WHAT MUST BE REDONE (honest scope)
1. Rebuild onion.c (and any Tor target) WITH include paths resolved, confirm members carry
   folded dimensions (uint8_t[505] etc.).
2. Re-run the R02b reference patch on the properly-built facts; measure real CAPACITY_EMITTED.
3. Re-adjudicate create_cell_init:110: capacity may now resolve (505); the INTERPROCEDURAL
   guard (caller parse_create2_payload) remains the real blocker -> still TOR-B3, still not
   "safe". Field identity + capacity would both be present; local bound still absent.
DO NOT (unchanged discipline):
  - infer 505 from source text / MAX_CREATE_LEN name; use the FOLDED typeFullName value only.
  - ship R02b without the GUARD-R01 capacity-control update (still owed).
  - treat enum-sized arrays as resolved (they are not folded; abstain).

## STATUS
CONST-EXPR-R01 characterization done; it CORRECTED a prior error. Object-like macro
dimensions DO fold into typeFullName when includes resolve; Tor's uint8_t[] was a flat-scan
artifact. No const-expr export layer is needed for macro cases (only enum/raw-literal-arith
remain unfolded, and those are rare / abstainable). Engine still frozen at R02a.1
(9c535347e330c483), core 7ad2880e04e84fd5, tcpdump 11, raft 8, canonical 31/31 — UNCHANGED.
Next: rebuild Tor with includes, replay R02b, measure real capacity yield.
