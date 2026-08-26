# ARRAY-DIM-R01 — ARRAY EXTENT RECOVERY CHARACTERIZATION. Measurement only. No implementation.
# Question: is the fixed-array dimension lost from member.type_full_name (uint8_t[]) present
# elsewhere in EXPORTED facts (structured), not merely in source text?

## FIXED POPULATION (from R02b): 10 Tor field-array operands, all UNKNOWN_ARRAY_DIMENSION.
Distinct underlying members: onionskin, reply, node_id (3 unique declarations).

## KEY FINDING: dimension IS exported — but SYMBOLIC, in member.code (not type_full_name)
The export's members.tsv carries BOTH m.typeFullName AND m.code. For macro-sized arrays:
  onionskin : code='onionskin[MAX_CREATE_LEN]'   type_full='uint8_t[]'
  reply     : code='reply[MAX_CREATED_LEN]'      type_full='uint8_t[]'
  node_id   : code='node_id[DIGEST_LEN]'         type_full='uint8_t[]'
So the DECLARATOR (with its dimension expression) survives in member.code; the DIMENSION is
lost only from typeFullName. Classification of the 3 distinct members:
  DIMENSION_PRESENT_AS_LITERAL:        0
  DIMENSION_SYMBOLIC (macro name):     3   [DIGEST_LEN, MAX_CREATED_LEN, MAX_CREATE_LEN]
  DIMENSION_NOT_IN_CODE:               0

## IS THE MACRO VALUE IN EXPORTED FACTS? — NO
Searched literals.tsv (no name->value binding), identifiers (DIGEST_LEN appears but type=ANY,
no value), type_decls (no size-encoding full_name). The macro VALUE is NOT exported anywhere
structured. Only the macro NAME is visible (in the declarator expression).
=> SYMBOLIC_DIMENSION_VISIBLE, VALUE_UNRESOLVED.

## CONTROL: fixture where dimension SURVIVES — pinpoints the divergence
Fixture (R02b derives capacity fine):
  reply: code='reply[16]'  type_full='char[16]'   <- LITERAL dimension -> folded into typeFull
Tor:
  onionskin: code='onionskin[MAX_CREATE_LEN]'  type_full='uint8_t[]'  <- MACRO -> NOT folded
DIVERGENCE LOCATED: Joern's C frontend constant-folds LITERAL array dimensions into
typeFullName (char[16]) but does NOT expand MACRO-sized dimensions (leaves uint8_t[]). The
declarator text is preserved in member.code either way. So the problem is specifically:
  MACRO-SIZED ARRAYS LOSE THE DIMENSION VALUE (not "Tor arrays in general").
Literal-sized Tor arrays (if any) would keep it; these 3 happen to all be macro-sized.

## ACCEPTANCE OUTCOME: SYMBOLIC_DIMENSION_VISIBLE_VALUE_MISSING
NOT "DIMENSION_NOT_EXPORTED" (the dimension EXPRESSION is exported in member.code).
NOT "DIMENSION_RECOVERABLE_FROM_EXISTING_FACTS" (the VALUE is not in any exported fact).
The honest state: the frontend exports the symbolic dimension but not its value; recovering
capacity requires resolving the macro constant (MAX_CREATE_LEN=505, etc.), whose value is
absent from the current export.

## WHAT THIS DOES AND DOES NOT JUSTIFY
Does NOT justify (per milestone rules):
  - parsing member.code with a regex to grab the macro NAME then GREPPING SOURCE for its
    #define — that proves the source has it, not that Fable exported a usable relation.
  - inferring 505 from MAX_CREATE_LEN or source text to force the Tor site.
Does justify a FUTURE, characterized milestone (NOT R01, NOT now):
  CONST-EXPR-R01 — export macro/const-expression VALUES from the frontend.
  The frontend (Joern c2cpg) would need to emit a name->value table for object-like macros
  / const ints (a #define or const table), OR emit the array TYPE node's resolved extent.
  Only THEN could a member's symbolic dimension resolve to a capacity. This is a
  FRONTEND/EXPORT change, not a normalizer change.
Also viable and NARROWER: for LITERAL-sized struct arrays (dimension already in typeFullName
or member.code as a number), R02b already works via the members type. That path needs no new
layer -- but the 3 Tor members here are all macro-sized, so they get 0 from it.

## STATUS
Characterization complete. Result: SYMBOLIC_DIMENSION_VISIBLE_VALUE_MISSING. The array
dimension for Tor's onionskin/reply/node_id is exported as a macro NAME in member.code, but
the macro VALUE is not in any exported fact, and typeFullName drops it (uint8_t[]) because
c2cpg does not constant-fold macro dimensions. R02b stays PARKED (no capacity to unlock on
these sites without the macro value). Next build (if pursued) is a FRONTEND const-expression
export (CONST-EXPR-R01), characterized separately -- NOT a normalizer patch, NOT source
grepping. Engine frozen at R02a.1 (9c535347e330c483), core 7ad2880e04e84fd5, tcpdump 11,
raft 8, canonical 31/31 — all UNCHANGED (no code touched this milestone).
