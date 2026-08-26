# JS-STATE-R10 — Comparison-Operator Fidelity

**Characterization only. Nothing implemented.** R07 unchanged. No
`ComparisonCoercionFact`, no new operator sets, no Family-B detector.

Core question: **can Fable obtain a first-class, structurally reliable
distinction between JavaScript `==`/`!=` and `===`/`!==` without inferring it
from arbitrary enclosing source text?**

---

## Layer 1 — CPG/AST node properties beyond the fields already queried

Every property on every equality-family operator node was enumerated via
`propertiesMap` (not just `name`/`methodFullName`/`typeFullName` as in R09):

```text
value ==  "admin"   ORDER, CODE, COLUMN_NUMBER, METHOD_FULL_NAME, LINE_NUMBER,
value === "admin"   TYPE_FULL_NAME, DISPATCH_TYPE, NAME
```

The complete property set is `{ORDER, CODE, COLUMN_NUMBER, METHOD_FULL_NAME,
LINE_NUMBER, TYPE_FULL_NAME, DISPATCH_TYPE, NAME}` (plus `ARGUMENT_INDEX` when
nested). Measured collapse:

| Source | `NAME` / `METHOD_FULL_NAME` |
|---|---|
| `==` | `<operator>.equals` |
| `===` | `<operator>.equals` |
| `!=` | `<operator>.notEquals` |
| `!==` | `<operator>.notEquals` |

**LAYER 1 RESULT: FAIL.** No property preserves the operator token. This
extends R09's finding to the strict-inequality pair (`!=`/`!==`), which R09
had not tested, and confirms the collapse is systematic across the whole
equality family rather than specific to `==`.

Incidental finding: `COLUMN_NUMBER` on the operator node marks the **start of
the whole binary expression** (i.e. the left operand's position), not the
operator's position. So the operator node's own column carries no operator
location information.

## Layer 2 — Parser representation upstream of the CPG

Not separately instrumented. The loss point is nonetheless localized by Layer
1 + Layer 3 together: the operand **spans** survive into the CPG with distinct
positions (Layer 3 below), which means positional information is preserved
through lowering while the operator *token identity* is discarded. The
collapse is therefore in jssrc2cpg's AST→CPG operator mapping (both tokens map
to one `<operator>.equals` / `<operator>.notEquals` symbol), not in the
parse/position pipeline. Confirming this inside Babel/astgen would require
instrumenting the frontend itself, which is out of scope for a
characterization milestone and is not needed for the R10 decision.

## Layer 3 — Source location fidelity (span slicing)

This is the layer that resolves R10.

Operands carry **independent** line and column positions in the CPG:

```text
value === "admin"    arg1 line=7 col=31 code='value'    arg2 line=7 col=41
a == b === c         arg1 line=10 col=31 code='a == b'  arg2 line=10 col=42   (outer)
                     arg1 line=10 col=31 code='a'       arg2 line=10 col=36   (inner)
a /* == */ === b     arg1 line=12 col=31 code='a'       arg2 line=12 col=46
a\n  ===\n  b        arg1 line=14 col=6  code='a'        arg2 line=16 col=6
```

This permits a **bounded, structural extraction** that is categorically
different from searching `node.code` for `"=="`: compute
`end_of_left = left.column + len(left.code)`, then slice the source strictly
between `end_of_left` and `right.column`. The operator is the only syntactic
material that can occupy that gap.

Index convention was measured, not assumed: **lines are 1-based, columns are
0-based.** (An initial run using 1-based for both produced a consistent
one-character left overshoot, e.g. gap `'e =='` instead of `' =='` — visible
in the raw output and corrected before the acceptance run.)

### Acceptance matrix — measured result

Gap-slice + comment/string stripping + operator tokenization over the bounded
span only:

| Fixture | Recovered gap | Operator | Expected | |
|---|---|---|---|---|
| `value == "admin"` | `' == '` | `==` | `==` | OK |
| `value === "admin"` | `' === '` | `===` | `===` | OK |
| `value != "admin"` | `' != '` | `!=` | `!=` | OK |
| `value !== "admin"` | `' !== '` | `!==` | `!==` | OK |
| `a == b === c` (outer) | `' === '` | `===` | `===` | OK |
| `a == b === c` (inner) | `' == '` | `==` | `==` | OK |
| `"a == b" === value` | `' === '` | `===` | `===` | OK |
| `a /* == */ === b` | `' /* == */ === '` | `===` | `===` | OK |
| multiline `a\n===\nb` | `'\n      ===\n      '` | `===` | `===` | OK |
| `d! === b` (TS non-null) | `' === '` | `===` | `===` | OK |

```text
R10 ACCEPTANCE: 10/10
```

Each adversarial control is defeated for a *structural* reason, not
incidentally:

- **String-literal confusion** (`"a == b" === value`): the `==` inside the
  string lies within the **left operand's own span**, so it is never inside
  the sliced gap. Span-bounding — not string cleverness — excludes it.
- **Comment confusion** (`a /* == */ === b`): the `==` *is* inside the gap
  here, so bounding alone is insufficient; it is removed by comment stripping
  applied **only to the bounded gap**, where a full lexer is tractable.
- **Chained comparison** (`a == b === c`): both operators recovered
  independently, because each comparison node has its own operand spans. The
  inner `a == b` is the outer node's left operand, so the outer slice starts
  after it.
- **Multiline**: spans cross lines; multi-line slicing recovers the operator
  intact.
- **TS non-null assertion** (`d! === b`): probes the overshoot risk found
  during index calibration — a left operand whose final character is
  punctuation. Recovered cleanly with correct 0-based columns.

## Verdict against R10's promotion criterion

> R10 PASS only if operator identity is recovered independently for the
> comparison node itself across adversarial lexical controls, with zero
> confusion between operators appearing in strings/comments/enclosing
> expressions.

**Criterion met: 10/10, zero confusions.**

However, the honest classification is not a simple PASS, because R10's *core
question* asked for recovery **"without inferring it from arbitrary enclosing
source text."** Span slicing is emphatically **not** arbitrary — it is bounded
by two structurally-derived positions and cannot see anything outside them —
but it is still a **source-text-dependent** recovery, not a CPG semantic fact.
That distinction matters for promotion and should not be blurred:

```text
LAYER 1 (semantic CPG property):   FAIL — token collapsed, no property retains it
LAYER 2 (upstream parser):          loss localized to AST->CPG operator mapping
LAYER 3 (structural span slicing):  PASS — 10/10 on adversarial matrix
LAYER 4 (raw code string search):   NOT USED — and demonstrably unnecessary
LAYER 5 (frontend patch):           NOT REQUIRED for correctness, but see below
```

```text
CLASSIFICATION: FRONTEND_GAP_CONFIRMED (semantic layer)
                + STRUCTURAL_RECOVERY_AVAILABLE (span layer)
```

R09's thesis-level conclusion **stands unmodified**: the frontend does collapse
the vulnerable operator and its one-character security fix into the same CPG
representation. R10 does not overturn that. What R10 adds is that the
collapse is recoverable *outside* the semantic fact layer, at a cost.

### Known limitations of span recovery (disclosed, not minimized)

1. **Requires source availability at analysis time.** The CPG does not store
   file content by default (`--enable-file-content` is off). Span recovery
   therefore depends on the original files still being present and byte-identical
   to what was parsed. A CPG analyzed detached from its source cannot use this.
2. **Requires a real lexer over the gap, not a regex.** The comment case proves
   bounding alone is insufficient. The prototype here used regex-based comment/
   string stripping, which is adequate for the tested matrix but is *not* a
   proven-complete JS lexer (e.g. regex literals containing `//` or `/*`,
   template literals with embedded expressions, nested comment-like sequences
   were not tested).
3. **Column-convention dependence.** Lines 1-based / columns 0-based was
   measured on this Joern version; it is an undocumented convention that could
   change and would silently produce off-by-one gaps.
4. **`len(code)` as the left operand's extent** assumes `code` is the exact
   source slice with no normalization. True across this matrix; not proven in
   general (e.g. operands whose `code` Joern rewrites during lowering).

These are why the sound long-term fix remains frontend-level, even though
recovery is available today.

---

## Next milestone (nominated only — not implemented)

**JS-STATE-R11 — Family-B Semantics Characterization**, now unblocked, with
one added precondition.

R09 already established the other three evidence components (operand type
domains PARTIAL-but-usable, `x == null` idiom structurally identifiable,
security-decision use available via the existing sink profile). R10 supplies
the missing fourth. R11 should therefore characterize:

```text
loose comparison (operator recovered per R10)
+ operand-domain evidence (R09)
+ null-idiom exclusion (R09)
+ coercion-relevant domain relationship
-> candidate
```

with the acceptance anchor already built: **R09's B1 must become
distinguishable from B2** (byte-identical apart from the operator).

**Added precondition for R11:** before span recovery is used in any promoted
fact, it must be hardened and re-tested against the four limitations above —
in particular replacing regex stripping with a real bounded lexer, and adding
regex-literal and template-literal adversarial cases. R10 measured
*feasibility*; it did not establish *production robustness*, and those are
different claims.

**Dominant residual risk for Family B remains R09's finding, not R10's:**
`ANY`-typed operands are extremely common in real JS (the CVE's own left
operand is `ANY`), so "not proven same domain" is far too weak to serve as
positive evidence. That, not operator fidelity, is now the hard problem.

---

## Thesis-relevant conclusion (R09 conclusion, refined by R10)

R09's statement stands, with an important qualification R10 adds:

> **Bug-family support is bounded by frontend semantic fidelity as well as
> downstream analysis capability.** In R09, a vulnerability family with
> source-confirmed security evidence could not be implemented soundly because
> the frontend collapses the vulnerable operator and its one-character
> security fix into the same CPG representation.

R10's refinement:

> **Frontend semantic loss is not always terminal.** Where the frontend
> discards a semantic distinction but preserves *positional* fidelity, the
> distinction can sometimes be reconstructed structurally — bounded by derived
> spans rather than by searching text. This shifts the finding from "family
> blocked" to "family implementable at a disclosed cost, outside the semantic
> fact layer," which is a materially weaker but still real dependency, and one
> that must be recorded as such rather than hidden inside a fact that looks
> semantic.
