# JS-PROV-R26 — Re-export Chain Resolution: IMPLEMENTED, NOT CLOSED

**Status: the semantics work; the gate is not green. R26 is NOT promoted.**
`JS_PROV_R23B=30/31`, with one failure caused by fixture-set damage I
introduced during this revision.

## What works (measured)

Re-export chains resolve transitively to a terminal declaration, with the chain
recorded and cycles terminating:

```text
realFn  -> base.ts::program:realFn   chain=[mid.ts:realFn, base.ts:realFn]
viaTop  -> base.ts::program:realFn   chain=[top.ts:realFn, mid.ts:realFn, base.ts:realFn]
missing -> ABSTAIN MEMBER_NOT_EXPORTED_BY_TARGET
spin    -> ABSTAIN REEXPORT_CYCLE      (true cycle, terminates, never loops)
export* -> ABSTAIN                     (no per-member identity to chain to)
```

Corpus C, exactly at the preregistered upper bound:

```text
established 63 -> 72     (+9, all via re-export chain)
abstentions: UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS 148 only
             (EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION now 0)
```

Corpus B CommonJS unchanged: 45 facts, 9 `validate()` resolutions.
`JS_PROV_R14=9/9`, `JS_PROV_R12=28/28`.

## Why it is not closed

The gate fixture directory already contained a differently-designed R26 fixture
set (`loopa/loopb` for a true cycle, `cyc1/cyc2` for a **terminating mutual**
re-export). I copied my own `cyc1.ts`/`cyc2.ts` into it, **overwriting the
terminating-mutual case with a true cycle**, and edited `use.ts` to match.

Reconstructing `cyc1/cyc2` fixed two teeth but left one:

```text
FAIL  R25 DECISIVE NEGATIVE: no ABSTAINED binding moves downstream :: ['fromCyc2']
```

`fromCyc2` appears in both the established and abstained sets — consistent with
more than one import binding sharing that local name across the merged fixture
set, but **not diagnosed**. Under the standing rule from R23c, a plausible
explanation is not a finding, and I am not recording one.

## Disposition

```text
SEMANTICS:        implemented and measured correct on the corpora
GATE:             30/31 -- NOT green
PROMOTION:        NO
CORPUS B:         unchanged (45 / 9)
R14, R12:         9/9, 28/28 unchanged
WRONG EVIDENCE:   none observed, but the failing tooth is precisely the control
                  that would detect fabrication, so this cannot be asserted
```

**The failing tooth is the R25 decisive negative** — the one control designed to
catch an abstained binding leaking downstream. It is the worst tooth to leave
red, and that is exactly why R26 is not promoted on "the numbers look right".

## Next step (before any further R26 work)

Rebuild the gate fixture set cleanly rather than patching it:

1. Give each R26 case its own file namespace so no two revisions can collide
   (`r26_chain_*.ts`, `r26_cycle_*.ts`, `r26_mutual_*.ts`).
2. Assert local-binding names are unique across the fixture set, so
   `est` / `abst` lookups keyed by local name cannot be ambiguous.
3. Re-run; if `fromCyc2` still appears in both sets, diagnose it rather than
   renaming around it.

Only then re-evaluate promotion.

## Discipline note

Two process failures here, both mine.

The first was mechanical: copying files into a shared fixture directory without
checking what was already there. The gate's fixture set is a test artifact with
its own design, and I treated it as a scratch space.

The second is the one worth keeping. Corpus C moved 63 -> 72 exactly as
preregistered, Corpus B was unchanged, and the semantics demonstrably work — so
there was real pressure to call the remaining red tooth a fixture artifact and
promote. The tooth in question is the fabrication control. A revision whose
measured behaviour is good and whose fabrication control is red is not a
revision that is nearly done; it is one whose most important claim is currently
unverified.

---

# R26 RECOVERY — CLOSED

`JS_PROV_R23B=33/33` (was 30/31). R14 9/9, R12 28/28.

## The open question, answered with evidence

> Is the defect in the RESOLVER, or in the GATE'S IDENTITY KEY?

**The gate's identity key.** Demonstrated, not inferred:

```text
app.ts:17   import { fromCyc2 } from './cyc1';     <- R23a-era file
r26_use.ts  import { ... as r26Mutual } ...        <- R26-era file
```

`app.ts` **also** imported a binding named `fromCyc2`. Two legitimately distinct
import records, in different modules, shared one human-readable local name. The
gate keyed `est` / `abst` on local name alone, so one established record and one
abstained record collapsed into an apparent contradiction.

The resolver was correct throughout. `ESTABLISHED n ABSTAINED` is now `{}` on
the rebuilt fixture set **and** on Corpus C.

This is why the recovery forbade renaming before diagnosis: renaming would have
turned the gate green while leaving the coarse key — and the next collision —
in place.

## Recovery performed, in the preregistered order

1. Fixtures rebuilt under `r26_chain_* / r26_cycle_* / r26_mutual_* /
   r26_missing_* / r26_star_*`, not repaired in place. The contaminated set is
   preserved at `evidence/contaminated_snapshot/` as evidence.
2. R23a/R23b originals (`app.ts`, `lib.ts`, `lib2.ts`, `danger.ts`,
   `reexport.ts`) left untouched; only R26-era files were replaced.
3. Both invariants added as permanent teeth.
4. `ESTABLISHED n ABSTAINED` computed explicitly: `{}`.
5. Origin traced before any rename.

## Results on the rebuilt set

```text
r26SingleHop  -> r26_chain_base:r26ChainTerminal   chain 2 hops
r26Transitive -> r26_chain_base:r26ChainTerminal   chain 3 hops
r26Mutual     -> r26_mutual_a:r26MutualTerminal    terminating mutual, NOT over-blocked
r26Missing    -> ABSTAIN MEMBER_NOT_EXPORTED_BY_TARGET
r26Spin       -> ABSTAIN REEXPORT_CYCLE            true cycle, terminates
r26Star       -> ABSTAIN MEMBER_NOT_EXPORTED_BY_TARGET   (export *)
```

## Corpora

```text
CORPUS C  established 63 -> 72   exactly the preregistered bound
          ESTABLISHED n ABSTAINED = {}
          L1 downstream 9 (unchanged -- R26 adds identities, not consumers)
CORPUS B  CommonJS unchanged: 45 facts, 9 validate() resolutions
```

# R26 FINAL VERDICT

```text
SEMANTICS:            chain resolution, transitive chains, terminating-mutual
                      non-over-blocking, true-cycle termination, missing-member
                      and export* abstention -- all demonstrated
GATE:                 33/33, including R26-SET-DISJOINTNESS and
                      R26-FIXTURE-INTEGRITY as permanent teeth
BLOCKER:              RESOLVED. Cause was the gate's identity key, not the
                      resolver -- traced to a duplicate local name across two
                      independent fixture modules.
CORPUS B / R14 / R12: unchanged
PROMOTION:            R26 CLOSED. Re-export chain resolution folded into
                      ImportBindingIdentityFact (already promoted at R25).
```

## Standing rules added

```text
R26-FIXTURE-INTEGRITY   every gate assertion key identifies exactly one
                        intended semantic case
R26-SET-DISJOINTNESS    ESTABLISHED n ABSTAINED = {} for binding identities
FIXTURE-DIRECTORY RULE  promotion fixtures are VERSIONED EXPERIMENTAL INPUTS,
                        not scratch files; existing fixtures must never be
                        overwritten by a later revision
```

The third is no longer housekeeping: violating it produced a misleading gate
state that took a full recovery cycle to unwind.

## Discipline note

The instinct on seeing `fromCyc2` in both sets was that the resolver had a
contradiction. It did not. A coarse gate key can manufacture the appearance of
an analyzer defect — which means a red tooth is evidence that *something* is
wrong, not evidence about *what*.

That cuts both ways against the earlier temptation: 30/31 was not "basically
passing", and it also was not proof the resolver was broken. Both readings were
unjustified until the two records were traced to their modules.
