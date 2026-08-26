# JS-PROV-R05 — Type-Recovery Reliability Characterization

**Characterization only.** No propagation implemented, no `jssrc2cpg` patch, no
ad-hoc spelling normalization. R07 unchanged.

R04 bounded what propagation can *mean*. R05 asks the prior question: **when is
Joern's recovered type evidence trustworthy enough to consume at all?**

Frozen guardrail (adopted verbatim from R04's cast finding):

> Argument→parameter propagation may preserve the type evidence **visible at a
> callsite**; it must never be described as recovering the concrete **runtime
> type** of the value.

---

## Headline: type recovery produces a demonstrably WRONG type on a common pattern

**R05-2 — short-name collision across modules. This is the most serious finding
of the milestone.**

```ts
// mod/other.ts
export class Router { m = 1 }

// main.ts
import { Router as R } from './mod/other';
class Router { r = 1 }            // a DIFFERENT, local class
const foreign = new R();          // constructs mod/other's Router
```

Measured:

```text
f2  ARG[foreign => main.ts::program:Router]     <-- WRONG
```

`foreign` is an instance of `mod/other.ts::program:Router`, but its
`typeFullName` reports the **local** `main.ts::program:Router`. Both
`TYPE_DECL`s exist and are correct and distinct:

```text
name=Router  id=167503724555  fullName=main.ts::program:Router       file=main.ts
name=Router  id=167503724570  fullName=mod/other.ts::program:Router  file=mod/other.ts
```

So the declarations are right; the **identifier→type binding resolved to the
wrong one by short name**. This is not imprecision (`ANY`) — it is a confident,
specific, incorrect answer. It is exactly the failure mode the instruction
"never equate types by short name alone" was written to prevent, and the
frontend is already doing it internally, upstream of anything Fable could gate.

This is now the **third** independent type-recovery defect on record:

| Milestone | Defect |
|---|---|
| JS-PROV-R02 | `router.get` → `methodFullName = ctx:cookies:<returnValue>:<member>(cookies):get` |
| JS-PROV-R04 | spurious `prop:ts::program:Base` (malformed `:` separator) |
| JS-PROV-R05 | imported-alias class resolves to a same-named local class |

And the malformed-separator defect **reproduces here**, confirming it is
systematic rather than a one-off: `viaFn`'s hints contain
`main:ts::program:Router` (colon where a dot belongs) alongside the correct
`main.ts::program:Router`.

## Q1 — Spelling normalization & structural identity

Three spellings for one type, from two construction sites in one file:

```text
viaNew (new Router())     => main.ts::program:Router
viaFn  (makeRouter())     => main.ts::program:Router:<init>
                             hints = main.ts::program:Router | Router | main:ts::program:Router
```

**A structural identity does exist** and should be preferred over strings:
`TYPE_DECL` carries a unique `id` and `filename`, and `TYPE` nodes link to it
via `referencedTypeDecl`.

**But it is not sufficient on its own**, because the same conceptual type has
*two* `TYPE_DECL`s — a real one and an external stub:

```text
Router  id=167503724555  fullName=main.ts::program:Router  ext=false  file=main.ts
Router  id=167503724581  fullName=Router                   ext=true   file=<unknown>
```

Naive decl-id comparison would call these different types. So the evidence
order is: **TYPE_DECL identity, *after* collapsing external stubs onto their
internal counterpart** — and that collapse can only be done by name, which
reintroduces exactly the ambiguity R05-2 shows to be unsafe when short names
collide. Circular; not resolvable at this layer.

## Q2 — `ANY` provenance

Seven candidate causes were tested. **They are not distinguishable**, with one
partial exception:

```text
cb as any               => ANY  /hints = <operator>.cast|ConcreteA|ANY
cb as unknown           => ANY  /hints = <operator>.cast|ConcreteA|ANY
cb as unknown as ConcreteA => ANY /hints = <operator>.cast|ConcreteA|ANY
```

All three casts are **byte-identical** in the export. `any` vs `unknown` was
already known indistinguishable (R04); this adds that *incompatible* casts are
indistinguishable from benign ones.

Partial exception: `<operator>.cast` appears **inside the hint list**, which is
a usable marker that *a cast occurred* — i.e. that the visible callsite type is
deliberately weaker or different from the producer type. That is the only
`ANY`-provenance signal recovered.

**Critical caveat on hints:** the hint set is identical across all three cast
sites and contains `ConcreteA` even for `cb as any`, which involves no
`ConcreteA` at all. Hints appear to be **aggregated per identifier rather than
per use site**, so they are polluted across sites and cannot be read as
site-specific evidence.

**Conclusion: `ANY = UNCONSTRAINED`, no concrete domain may be inferred behind
it** — reaffirming R11.

## Q3 — Evidence strength hierarchy

Only **three** of the five candidate categories are actually distinguishable:

| Category | Distinguishable? | Basis |
|---|---|---|
| `DECLARED` | YES | parameter `typeFullName` ≠ `ANY` and resolves to a non-external `TYPE_DECL` |
| `DYNAMIC_TYPE_HINT` | YES | separate `dynamicTypeHintFullName` field — but polluted per Q2 |
| `UNKNOWN` | YES | `ANY` |
| `FRONTEND_RECOVERED` | **NO** | indistinguishable from `DECLARED` — the CPG does not record *how* a `typeFullName` arose |
| `CALLSITE_OBSERVED` | N/A | would exist only once propagation is built |

**So `DECLARED > RECOVERED` cannot be asserted**, exactly as the prompt
cautioned. A `typeFullName` that came from an author's annotation and one the
frontend guessed (possibly wrongly, per R05-2) are the same field with no
provenance marker. This is a significant constraint on any strength hierarchy.

## Q4 — Aliases

```text
type RouterAlias = Router;
fAlias  PARAM[1:RouterAlias]
TYPE_DECL RouterAlias  id=167503724569  fullName=main.ts::program:RouterAlias
```

The alias gets its **own** `TYPE_DECL`, distinct from `Router` (id …555). It
does **not** resolve to the underlying declaration. So `RouterAlias` and
`Router` are different types by both string and decl identity, despite being
the same type in TypeScript.

Import aliases behave differently and worse — `import { Router as R }` does not
produce an alias decl; it mis-binds to the local `Router` (R05-2).

## Q5 — Interfaces / structural typing (critical for TS)

```text
f8(new RealRouter())  ARG => BLOCK
f8(structural)        ARG => ANY /hints = main.ts::program:HandlerLike|HandlerLike
                      PARAM[1:HandlerLike]
```

A plain object literal satisfying the interface (`structural`) reports
`HandlerLike` in its hints — **identically to how a nominal implementer would**.
The frontend reports the *interface* type, not the nominal runtime type.

**Direct consequence for JS-PROV:** a structural interface match must never be
treated as proof of framework or module identity. An object literal
`{ post(){} }` is reported as `HandlerLike`, the same as a real router would be.
This is precisely the `notFramework` negative control from JS-PROV-R01 — which
passed there only because that fixture used an inline object-literal *type*
rather than a declared interface. Against a declared interface, the R01
discriminator would be weaker than measured.

Also noted: `new RealRouter()` as an argument types as **`BLOCK`**, not a type
at all. Constructor-call arguments lose their type entirely at the callsite.

## Q6 — Unions

```text
f6(x: Router | Widget)   PARAM[1:ANY]        <-- union COLLAPSED at the parameter
TYPE node "Widget | Router" exists (id 167503724585, external)
f6(viaNew)        ARG => main.ts::program:Router
f6(new Widget())  ARG => BLOCK
```

The union type node exists in the type table but the **parameter reports
`ANY`** — union information is lost at exactly the position propagation would
consume it. Callsite alternatives remain separable only when the argument is a
plain identifier (not a constructor call).

R04's rule preserved: observed callsite types ≠ exhaustive parameter runtime
domain.

## Q7 — Generics

```text
idg<T>(x:T)   PARAM[1:T]     ARG[viaNew => main.ts::program:Router]
f7<T>(x:T)    PARAM[1:T]     ARG[viaNew => main.ts::program:Router]
```

The parameter type is literally `T`. **No instantiation information survives**
to the parameter or the return site. Bounded frontend limitation; generic
passthrough carries no concrete type.

## Q8 — Explicit casts

Covered under Q2. Summary: all cast forms collapse to `ANY`; the only recovered
signal is the presence of `<operator>.cast` in the hint list; the cast *target*
may appear in hints but the *producer* type does not. Per the frozen guardrail,
the runtime type must **not** be reconstructed from this.

## Q9 — Property and index access

```text
viaIndex = rec[key]   => main.ts::program:Router
                         hints = main.ts::program:Router | Router
                               | { [x: __ecma.String]: Router; }:<indexAccess>
viaField = (new RealRouter()).post  => (p: __ecma.String) => ANY
```

Index access **does** recover the declared index-signature value type, and the
hint even records the index-signature shape. Member access recovers a function
signature.

**R11/R12's warning is preserved and is now doubly load-bearing:** the declared
index-signature type is *not* proof of exhaustive runtime values. R12 showed
`rec["__proto__"]` yields an inherited `Object.prototype` value that the
signature says cannot occur — and R05 confirms the frontend will confidently
report `Router` for that read.

## Q10 — Cross-module stability (Corpus B)

Per-hop table for the `@koa/router` value in `paralect/koa-api-starter`
(measurements from R03/R04, engine unchanged):

| VALUE | LOCATION | TYPE_FULL_NAME | HINTS | EVIDENCE CLASS |
|---|---|---|---|---|
| `router` | defining module LOCAL | `@koa/router` | — | DECLARED/RECOVERED (indistinguishable) |
| `router` | exported symbol | — (module.exports of `router.routes()`) | — | n/a |
| `router` | callsite argument (×12) | `@koa/router` | — | same, stable |
| `router` | callee parameter | **`ANY`** | `[]` | UNKNOWN |

**Fidelity is lost at exactly one hop** — the callee parameter — and is stable
across all others. This corroborates R03 and adds that no dynamic hint fills
the gap either.

---

## Adversarial teeth summary

| Tooth | Result |
|---|---|
| R05-1 same type, spelling differs | 3 spellings incl. one malformed; needs decl identity |
| R05-2 same short name, diff modules | **WRONG TYPE — mis-binds to local class** |
| R05-3 imported alias | mis-binds (same defect as R05-2) |
| R05-4 `as any` | → `ANY`; cast marker in hints |
| R05-5 incompatible cast | → `ANY`; **indistinguishable from R05-4** |
| R05-6 union | collapsed to `ANY` at the parameter |
| R05-7 generic passthrough | parameter is `T`; no instantiation |
| R05-8 structural interface | object literal reports the interface, same as nominal |
| R05-9 property/index access | index-signature type recovered; not exhaustive (R12) |
| R05-10 cross-module replay | stable except the one parameter hop |

---

# JS-PROV-R05 VERDICT

```text
TYPE IDENTITY STABILITY:  UNRELIABLE for the cases that matter. TYPE_DECL
                          provides a structural id (+filename), which is the
                          right primitive — but each type ALSO has a duplicate
                          external stub decl, and collapsing stub onto real can
                          only be done by name, which is precisely what R05-2
                          proves unsafe. Circular at this layer.

SPELLING NORMALIZATION:   INSUFFICIENT and unsafe as a strategy. Three spellings
                          observed for one type (`X`, `X:<init>`, malformed
                          `main:ts::program:X`). Normalizing them would ALSO
                          merge the two genuinely-distinct same-named classes
                          from different modules.

ANY SEMANTICS:            ANY = UNCONSTRAINED, confirmed. The seven candidate
                          causes are NOT distinguishable. Only signal recovered:
                          `<operator>.cast` present in hints => the visible type
                          is deliberately weaker than the producer's.
                          HINTS ARE AGGREGATED PER IDENTIFIER, NOT PER SITE —
                          polluted across use sites, not site-specific evidence.

ALIASES:                  Type aliases get their OWN TYPE_DECL and do NOT
                          resolve to the underlying type. Import aliases are
                          worse: they mis-bind to a same-named local class.

INTERFACES:               Structural match reported IDENTICALLY to nominal.
                          A plain object literal reports the interface type.
                          Structural match must NEVER be treated as proof of
                          framework/module identity. This WEAKENS JS-PROV-R01's
                          `notFramework` discriminator against declared
                          interfaces (R01 tested only an inline object type).

UNIONS:                   COLLAPSED to ANY at the parameter — lost exactly where
                          propagation would consume it, despite the union TYPE
                          node existing in the type table.

GENERICS:                 No instantiation survives; parameter type is `T`.
                          Bounded frontend limitation.

CASTS:                    All forms (`as any` / `as unknown` / incompatible)
                          collapse to ANY and are mutually INDISTINGUISHABLE.
                          Cast target may appear in hints; producer type never
                          does. Runtime type must NOT be reconstructed.

PROPERTY/INDEX ACCESS:    Index-signature value type IS recovered (and the
                          signature shape appears in hints) — but per R12 this
                          is NOT proof of exhaustive runtime values; the
                          frontend will confidently report `Router` for a
                          prototype-reachable read.

CROSS-MODULE STABILITY:   STABLE except the single callee-parameter hop,
                          corroborating R03. No dynamic hint fills the gap.

SAFE INPUTS TO PROPAGATION:
  - argument is a plain IDENTIFIER (not a constructor call -> BLOCK, not a cast
    -> ANY),
  - whose typeFullName resolves to exactly ONE non-external TYPE_DECL,
  - whose short name is UNIQUE across the analyzed program (guards R05-2),
  - callee resolved to exactly one method (R04 Q9),
  - callee parameter is `ANY` and is not rest/defaulted (R04 Q5).

MUST-ABSTAIN CASES:
  - any short-name collision anywhere in the program (R05-2 mis-binding)
  - imported aliases
  - any argument whose hints contain `<operator>.cast`
  - constructor-call arguments (type as BLOCK)
  - union-typed and generic parameters
  - interface-typed parameters (structural match is not identity)
  - all property/index reads where the base's prototype is reachable (R12)

PROMOTION_READY: NO — and R05 has made the case stronger, not weaker.
                 R04 blocked on "we haven't measured the error rate."
                 R05 measured it and found a CONFIRMED WRONG TYPE on a
                 mainstream pattern (imported class + same-named local),
                 plus a third instance of the malformed-separator defect.
                 Propagation amplifies; amplifying a known-wrong signal is
                 worse than not propagating.

DOMINANT GAP:    Frontend type-binding CORRECTNESS, not coverage. The problem
                 is no longer "types are missing" (R03) or "propagation
                 semantics are undefined" (R04) but "some types the frontend
                 asserts confidently are simply wrong, and nothing in the
                 export marks them as guesses" (Q3: FRONTEND_RECOVERED is
                 indistinguishable from DECLARED).

NEXT MILESTONE:  JS-PROV-R06 — Type-Binding Defect Characterization &
                 Upstream Disposition. Two halves, characterization only:
                 (a) measure short-name-collision and malformed-separator
                     frequency across the existing real corpora (fxa,
                     node-oauth2-server, truthy, koa-api-starter) to establish
                     whether R05-2 is a fixture artifact or endemic;
                 (b) decide disposition — these are jssrc2cpg defects, not
                     Fable modelling gaps, so determine whether the correct
                     action is an upstream bug report + version pin rather
                     than a Fable-side workaround. R04 already concluded the
                     propagation layer belongs in Fable (option B); R05
                     suggests its INPUTS may need to be fixed upstream.
```

## Discipline note

R05 was nominated to measure an error rate before building an amplifier, and
it found something worse than a rate: a **specific, reproducible, confidently
wrong type** on a pattern (an imported class sharing a short name with a local
one) that is entirely ordinary in real TypeScript. Combined with Q3 — the
export does not distinguish an authored annotation from a frontend guess —
there is currently no way for a consumer to know which types to trust.

The safe-input list above is deliberately narrow enough that it would exclude
much of real code, including, on a strict reading, the Corpus-B routers if any
same-named `Router` existed elsewhere in that program. That narrowness is the
honest result, not a failure of the milestone.
