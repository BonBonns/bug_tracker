# JS-PROV-R26 — Bounded Re-Export Hop

Isolated revision with its own preregistration, freeze and negative controls, as
R25's closeout required. **`JS_PROV_R23B=25/25`**; R14 9/9, R12 28/28, R21 12/12.

## The gap (R23a → R23c → parked through R25)

```text
export { fDecl } from './lib'   ->   exports.fDecl = _lib.fDecl
```

RHS is a field access on an imported module object — no declaration identity.
9 of 13 Corpus-C relative abstentions were this shape.

## Implementation

One hop applied transitively with an explicit bound: resolve the RHS base local
→ its specifier → that file's export assignment → declaration identity. The
base and member are exported **structurally** (not parsed from the code string,
per R13).

## Preregistered invariants

```text
J1 R25 criteria still hold        PASS  L1=9, L2/L3/L5=0, L6=20
J2 Corpus B CommonJS unchanged    PASS  45 facts / 9 validate()  -- see below
J3 no member the target lacks     PASS  `notThere` abstains
J4 export * still abstains        PASS
J5 cycles terminate + abstain     PASS  REEXPORT_CYCLE on a TRUE cycle
J6 depth bounded and recorded     PASS  reexport_depth_bound on every fact
J7 WRONG                          0
J8 full chain recorded            PASS  e.g. [reexport.ts:fDecl, lib.ts:fDecl]
```

## J2 caught a regression I introduced

Widening `module_exports.tsv` from 5 to 7 columns silently zeroed the CommonJS
path — `module_specifier_resolution.py` reads a fixed width, so **Corpus B fell
from 45 facts to 0**. Every gate still passed at that moment, because no gate
exercises Corpus B directly.

Fixed by making the reader width-agnostic. This is the single most useful result
of the milestone: a schema widening is not a semantic change, which is exactly
why it slipped past the gates, and only the preregistered corpus invariant
caught it.

## Cycle control — my first fixture did not test what I claimed

The initial "cyclic" fixture (`cyc1 → cyc2 → cyc1.realInCyc1`) **terminates
legitimately** at a real declaration; it is a mutual re-export, not a cycle. The
guard was therefore untested by it. A true non-terminating cycle
(`loopa ⇄ loopb`, no declaration anywhere) was added and abstains with
`REEXPORT_CYCLE`. Both are retained: one proves the guard fires, the other
proves it does not over-block.

## Results

```text
FIXTURE
  viaReexport  ESTABLISHED  -> lib.ts::program:fDecl
               chain [reexport.ts:fDecl, lib.ts:fDecl]
               evidence IMPORT_NODE+EXPORT_ASSIGNMENT+REEXPORT_CHAIN
  fromCyc2     ESTABLISHED  -> cyc1.ts::program:realInCyc1  (3-hop, terminates)
  notThere     ABSTAIN  REEXPORT_MEMBER_NOT_EXPORTED_BY_TARGET
  spin         ABSTAIN  REEXPORT_CYCLE
  ns/fDefault  ABSTAIN  (unchanged)

CORPUS C
  import bindings established : 63 -> 72   (+9, all via re-export chain)
  EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION abstentions : 9 -> 0
  remaining abstentions : 148, all UNRESOLVED (bare packages)
  L1 = 9 (unchanged)   L2/L3/L5 = 0   L6 = 20

CORPUS B
  45 facts / 9 validate() resolutions, all REQUIRE_BINDING+EXPORT_ASSIGNMENT
```

All 9 re-export abstentions resolved — the preregistration allowed for fewer.
L1 did not move, because Corpus C's re-exported members are not consumed at
call sites the L1 consumer inspects; the identities are now available, not
obligated.

## Three superseded assertions, inverted rather than deleted

R26 changes behaviour R23b/R25 previously asserted. Those assertions were
**rewritten in place with a SUPERSEDED note**, not removed:

```text
"re-export -> ABSTAINS"                  ->  "-> RESOLVES via the R26 chain hop"
"evidence == IMPORT_NODE+EXPORT_ASSIGNMENT" -> "startswith(...)" (chain suffix)
"re-export never reaches the consumer"   ->  "reaches it ONLY because R26
                                              established it"
```

The decisive R25 negative control — only ESTABLISHED bindings move downstream —
is untouched and still passes.

# JS-PROV-R26 VERDICT

```text
RE-EXPORT HOP:        IMPLEMENTED, bounded (depth 8), transitive, chain recorded.
GATE:                 JS_PROV_R23B=25/25 (9 producer + 8 consumer + 8 re-export).
REGRESSION:           R14 9/9, R12 28/28, R21 12/12.
J2 REGRESSION FOUND:  YES -- schema widening zeroed Corpus B; caught only by the
                      preregistered corpus invariant, not by any gate. Fixed.
CYCLE GUARD:          Fires on a TRUE cycle; does not over-block a terminating
                      mutual re-export. First fixture was wrong and was replaced.
CORPUS C:             +9 import identities; re-export abstentions 9 -> 0.
CORPUS B:             unchanged.
WRONG:                0.

DOMINANT REMAINING GAP: bare-package specifiers (148 Corpus-C abstentions) --
                      correct by construction, not a defect.
NEXT:                 R24 remains BLOCKED under its original E1-E7 criteria.
```

## Discipline note

Two self-inflicted defects in one milestone, both caught by preregistered
checks rather than by gates: a schema widening that silently zeroed a corpus,
and a negative control that did not test what its name claimed. The gates were
green through both.

That is the third time in this line that a green suite coexisted with a real
defect (R23c's dead-ended fact, R25's `ns` risk, now these). The pattern is
consistent enough to state plainly: **gates verify what they were written to
verify, and a milestone's own preregistered invariants are what catch the
things nobody thought to gate.**
