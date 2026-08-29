# Scanner-coverage capability plan (frozen design; no model calls)

Motivated by the Magma frozen-scanner measurement: real-code writes use representation
shapes the scanner does not model (0/6 parsed bug-sites recognized). This plan adds
**general evidence models for four representation shapes** — NOT four bug-name-specific
aliases.

## Corpus discipline (frozen)

- **Magma = development/regression corpus only.** All 7 mapped bugs are development sites,
  never confirmatory. Adding a capability and re-measuring on the bug that motivated it is
  training on the test set.
- **A separate, independently frozen held-out corpus supplies confirmatory evidence** — a
  statement-level source such as **SecVulEval** (real, statement-labeled). It must be
  fetched, filtered to the destination-capacity write property, and frozen **before** any
  capability is evaluated on it, and never inspected while tuning.

## Four capabilities (increasing complexity; each a general model)

1. **Address-of indexed destination** `&(base[index])`
   - Bind base identity, offset (index), element width, and **remaining** capacity
     (`capacity(base) − offset`). Covers the SND positioned-write family.
   - Must NOT assume struct-field or realloc capacity unless independently established;
     if `capacity(base)` is unresolved, the op is `additional_evidence_required`, not a
     guess.
2. **Transparent wrapper summaries**
   - Infer that a callee writes its length argument into its destination parameter, from
     the **callee body** or a **trusted contract channel** — never from the function name.
     Covers `ascii2ebcdic`-shaped wrappers.
3. **Pointer-walk writes**
   - Track repeated writes through an incremented pointer (`*p++ = …` / `p[k]` in a loop);
     bind the loop/count bound and remaining capacity. Covers PNG palette population.
4. **External decoder contracts**
   - Model output extent and destination capacity for functions such as `inflate`, via
     explicit **semantic library contracts** (kept separate — not inferred from a body).

## Per-capability requirements (ALL must hold before a capability is accepted)

- synthetic **positive** and **negative** controls (recognized when it should be; not when
  it shouldn't);
- **declaration/identity binding** (the base/dest resolved to a real declaration, not a
  name match);
- **offset and unit handling** (element width / `sizeof(T)` kept symbolic; byte vs element
  consistent);
- **conflict/ambiguity controls** (multiple/uncertain bases → abstain, never guess);
- **unchanged existing verdicts** outside the new representation form (regression: the
  frozen Juliet + existing corpus verdicts do not move);
- **Magma development-site recovery** (the motivating dev site is now recognized);
- **exact-site measurement on the separately frozen held-out corpus** (confirmatory).

## Order of work

Capability 1 first (foundation; least complex). Each capability is implemented as a general
evidence model with its control harness, verified for no-regression on existing verdicts,
then measured on held-out data. No capability is justified or evaluated by the Magma bug
that motivated it.
