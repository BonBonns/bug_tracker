# TOR-SCAN-R01 — Tor build-hygiene replay. Smoke test: does onionskin resolve to uint8_t[505]?
# RESULT: PARTIAL / SMOKE TEST FAILS under realistic builds. Precise root cause characterized.
# No engine change; frozen state untouched.

## SMOKE TEST OUTCOME (multiple build configs tried)
  single-file onion.c + --include src:   0 members (header structs not emitted in single-file)
  directory core/or, flattened:          onionskin uint8_t[], node_id uint8_t[20]
  directory core/or, src/ include root:  onionskin uint8_t[], node_id uint8_t[20]  <- best
  self-contained torlike.c (CONST-EXPR): onionskin uint8_t[505]  (RESOLVED — but synthetic)
SMOKE TEST (onionskin==uint8_t[505] on REAL Tor): FAIL.
Partial success: node_id -> uint8_t[20] RESOLVES (DIGEST_LEN folds).

## PRECISE ROOT CAUSE (measured, not guessed)
Both members are in the SAME header onion.h:
  onion.h:35  uint8_t onionskin[MAX_CREATE_LEN];   MAX_CREATE_LEN=(CELL_PAYLOAD_SIZE-4), or.h
  onion.h:57  uint8_t node_id[DIGEST_LEN];          DIGEST_LEN=20, digest_sizes.h
onion.h includes crypto_ed25519.h (line 18) -> transitively pulls digest_sizes.h -> DIGEST_LEN
DEFINED when the struct is parsed -> node_id resolves to [20].
onion.h does NOT include or.h. CELL_PAYLOAD_SIZE is only defined by or.h, which is included
by onion.c (line 41), NOT by onion.h. When c2cpg parses the header's struct, CELL_PAYLOAD_SIZE
is UNDEFINED -> MAX_CREATE_LEN can't expand -> onionskin collapses to uint8_t[].

## THEREFORE — CORRECTED UNDERSTANDING (refines the CONST-EXPR-R01 correction)
The CONST-EXPR-R01 self-contained test proved c2cpg CAN fold nested-macro arithmetic
(MAX_CREATE_LEN -> 505) WHEN CELL_PAYLOAD_SIZE is defined before the struct. But in REAL Tor,
onion.h's struct is parsed WITHOUT or.h in scope, so the macro is genuinely undefined at that
point. This is NOT merely "I forgot include paths" (my earlier framing) — it is a HEADER
DEPENDENCY property: onion.h relies on its includer having already defined CELL_PAYLOAD_SIZE.
c2cpg parses each header/TU as it finds it; there is no config that makes onion.h's struct see
or.h's macro unless a TU includes or.h THEN onion.h in that order and c2cpg emits members for
that TU's view.

## HONEST STATE OF THE THREE COMPETING CLAIMS
  (1) ARRAY-DIM-R01: "dimension value not exported"        -> WRONG (folds when macro defined)
  (2) CONST-EXPR correction: "just my flat scan hygiene"   -> PARTLY RIGHT but INCOMPLETE
  (3) TOR-SCAN-R01 (this): "onion.h struct can't see CELL_PAYLOAD_SIZE because onion.h doesn't
      include or.h; realistic builds parse the header without it" -> the ACCURATE account.
node_id[DIGEST_LEN]=20 folds (its macro's header IS transitively included); onionskin does not
(or.h is not). Both facts are consistent with (3) and refute the simpler (1) and (2).

## IMPLICATION FOR R02b CAPACITY REPLAY
On a realistic Tor build, onionskin capacity is STILL not resolvable from typeFullName (it is
uint8_t[]), so R02b would emit no capacity for it — for a DIFFERENT reason than first thought
(header dependency, not export gap, not field identity). node_id-style members (macro defined
via transitively-included header) WOULD resolve. So R02b yield on Tor is NON-ZERO but PARTIAL,
gated by each member's header-include situation.
Options (each a separate future milestone, NOT done here, NONE via source-text inference):
  A. Build TUs so each struct's size macros are in scope (compilation-database driven build:
     use Tor's real compile commands so or.h precedes onion.h). Highest fidelity.
  B. Accept partial resolution: members whose size macro resolves (node_id) get capacity;
     others (onionskin) abstain. Honest, no new risk.
  C. A frontend const/enum export (the original CONST-EXPR idea) would NOT help here — the
     macro isn't unresolved-but-present; it's genuinely UNDEFINED in onion.h's parse scope.
DO NOT infer 505 from MAX_CREATE_LEN/or.h by reading source; that is not a Fable-derived fact.

## STATUS
Smoke test FAIL on real Tor (onionskin uint8_t[]); node_id resolves ([20]). Root cause:
onion.h struct references CELL_PAYLOAD_SIZE without including or.h; realistic header parse has
it undefined. This is the accurate, final characterization, refining the earlier flat-scan
framing. No R02b replay performed (smoke test gate not passed for onionskin). Engine frozen at
R02a.1 (9c535347e330c483), core 7ad2880e04e84fd5, tcpdump 11, raft 8, canonical 31/31 —
UNCHANGED. Next (if pursued): compilation-database-driven build (option A) so size macros are
in scope, then re-run smoke test before any capacity replay.
