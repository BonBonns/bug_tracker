# JS-STATE-R11 — Family-B Operand-Domain Semantics Characterization

**Characterization only. Nothing implemented.** R07 unchanged. No
`ComparisonCoercionFact`, no vulnerability verdict, no detector.

Per R10's disposition, operator recovery is treated as **answered** and is not
revisited here. R11 asks only:

> What positive evidence can establish that abstract equality is comparing
> values from meaningfully different coercion domains — especially when one or
> both operands are typed `ANY`?

---

## Permanent invariant established by this milestone

```text
ANY / unknown  ≠  OBJECT  ≠  MIXED     ==>  DOMAIN_NOT_ESTABLISHED
```

`ANY` is **not a domain**. It is the absence of one. This is recorded as a
hard rule because the alternative — treating "types not proven equal" as
evidence of difference — degenerates into "`==` is suspicious," which is
unusable in plain JavaScript.

---

## Measured evidence, per operand

Fixture: `fixture/domains.ts`, seven cases, real Joern run.

| Case | Operand | STATIC_TYPE | HINTS | PRODUCER |
|---|---|---|---|---|
| A explicit-different | `a` | `__ecma.Number` | — | `const a = 1` |
| | `b` | `__ecma.String` | — | `const b = "1"` |
| B same-domain | `c` | `__ecma.String` | — | `const c = "x"` |
| | `d` | `__ecma.String` | — | `const d = "x"` |
| C nullish idiom | `value` | `string \| __ecma.Null \| ANY` | — | — |
| | `null` | `__ecma.Null` | — | — |
| D ANY vs explicit | `unknownValue` | `ANY` | — | — |
| | `"secret"` | `__ecma.String` | — | — |
| E both ANY | `x` | `ANY` | — | — |
| | `y` | `ANY` | — | — |
| F **CVE shape** | `users[name]` | **`ANY`** | — | — |
| | `password` | `ANY` | — | `const password = request.body.password` |
| G explicit conv + strict | `String(a)` | `ANY` | `String` | — |
| | `b` | `__ecma.String` | — | `__ecma.String` |

### Which domain evidence axes actually carry information

| Axis | Availability |
|---|---|
| `STATIC_TYPE` | **STRONG** where TS annotations or literal initializers exist (A, B, C, G) |
| `LITERAL_DOMAIN` | **STRONG** — literals type precisely (`__ecma.Number`, `__ecma.String`, `__ecma.Null`) |
| `PRODUCER_DOMAIN` | **PARTIAL** — the assignment that produced a local is recoverable via REF (A, B, F-right), giving literal-derived domains in A/B |
| `DYNAMIC_TYPE_HINTS` | **WEAK** — empty on every operand except G (`String`) |
| `PROPERTY/INDEX_ACCESS_BASE` | **STRONG, and the key finding — see below** |
| `SOURCE_PROVENANCE` | available (`request.body.password` traceable) but yields `ANY` |
| `DOMAIN_RESOLUTION` | see classification table |

---

## The central finding: the CVE's domain *is* recoverable, and that is exactly why it stays undetectable

Case F is the historical CVE shape. The index-access node itself types as `ANY`:

```text
indexAccess code=users[name] typeFullName=ANY
```

But probing the **base** rather than the result recovers a fully-resolved
index signature:

```text
base arg1 code=users -> { [x: __ecma.String]: __ecma.String; }
LOCAL users typeFullName={ [x: __ecma.String]: __ecma.String; }
```

So `PROPERTY/INDEX_ACCESS_BASE` recovery **works**: `users[name]` has
`LEFT_DOMAIN = STRING`, derived structurally from the base's declared index
signature — precisely the producer-history recovery R11 was asked to
investigate. That is a genuine positive result for the domain-inference
question in general.

**And it makes the CVE *less* detectable, not more.**

The vulnerability exists because `users["__proto__"]` returns
`Object.prototype` — an **`OBJECT`-domain value that the declared
`Record<string, string>` type says cannot occur**. TypeScript's declared type
is, at runtime, a lie for exactly the inherited-property key that constitutes
the attack. Therefore:

- Perfect declared-type recovery yields `LEFT_DOMAIN = STRING`.
- The right operand (`password`, from `request.body.password`) is `ANY`.
- `DOMAIN_RELATION` is `UNKNOWN` (STRING vs ANY) — and had the right operand
  been annotated `string`, it would have been **`SAME`**, i.e. actively
  classified as *non-coercive*.

> **Declared-type domain reasoning cannot detect a vulnerability whose entire
> mechanism is a runtime value escaping its declared domain.** For this bug
> class the declared type is not merely insufficient evidence — it is
> actively misleading evidence pointing the wrong way.

This was not the anticipated outcome ("domains are UNKNOWN on most real JS").
The truth is sharper: for the one confirmed CVE, the domain is *knowable* and
*wrong*.

---

## Classification of all cases

Operator identity per R10 (span recovery); all cases `==` except G (`===`).

```text
caseA_explicitDifferent
  OPERATOR_IDENTITY: ABSTRACT_EQUALITY
  LEFT_DOMAIN: NUMBER      RIGHT_DOMAIN: STRING
  DOMAIN_RELATION: DIFFERENT     NULLISH_IDIOM: NO
  SECURITY_DECISION: YES (fixture sink)
  RESULT: COERCIVE_SECURITY_COMPARISON_SHAPE

caseB_sameDomain
  OPERATOR_IDENTITY: ABSTRACT_EQUALITY
  LEFT_DOMAIN: STRING      RIGHT_DOMAIN: STRING
  DOMAIN_RELATION: SAME          NULLISH_IDIOM: NO
  SECURITY_DECISION: YES
  RESULT: NONCOERCIVE_COMPARISON

caseC_nullishIdiom
  OPERATOR_IDENTITY: ABSTRACT_EQUALITY
  LEFT_DOMAIN: STRING|NULLISH    RIGHT_DOMAIN: NULLISH (literal __ecma.Null)
  DOMAIN_RELATION: (not evaluated)  NULLISH_IDIOM: YES  <-- hard negative tooth
  SECURITY_DECISION: YES
  RESULT: INTENTIONAL_NULLISH_COMPARISON

caseD_anyVsExplicit
  LEFT_DOMAIN: UNKNOWN (ANY)     RIGHT_DOMAIN: STRING
  DOMAIN_RELATION: UNKNOWN       NULLISH_IDIOM: NO
  RESULT: DOMAIN_UNKNOWN   (abstain -- NOT "different")

caseE_bothAny
  LEFT_DOMAIN: UNKNOWN           RIGHT_DOMAIN: UNKNOWN
  DOMAIN_RELATION: UNKNOWN
  RESULT: DOMAIN_UNKNOWN

caseF_cveShape   <-- THE HISTORICAL CVE
  OPERATOR_IDENTITY: ABSTRACT_EQUALITY
  LEFT_DOMAIN: STRING  (recovered from base index signature {[x:string]:string})
  RIGHT_DOMAIN: UNKNOWN (ANY, via request.body.password)
  DOMAIN_RELATION: UNKNOWN       NULLISH_IDIOM: NO
  SECURITY_DECISION: YES (authenticate)
  RESULT: DOMAIN_UNKNOWN   <-- CVE NOT DETECTED, and would be classified
                               NONCOERCIVE if the right operand were annotated

caseG_explicitConvStrict
  OPERATOR_IDENTITY: STRICT_EQUALITY (R10 span recovery)
  RESULT: NONCOERCIVE_COMPARISON  (strict equality performs no coercion)
```

### Nullish idiom — confirmed as a hard negative tooth

Case C is structurally identifiable **without source-text matching**: the
right operand is a `LITERAL` whose `typeFullName` is exactly `__ecma.Null`.
Per instruction this is excluded *even when* the domain relation would read
`UNKNOWN vs NULLISH`. Recorded as a permanent exclusion, not a heuristic.

---

## Answer to R11's central question

**Positive domain evidence is available in more places than expected — but not
where Family B needs it.**

- Provable domains exist for: literals, TS-annotated locals, literal-initialized
  `const`s, and (new finding) index-access bases with declared index signatures.
- Provable domains do **not** exist for: values crossing an external/request
  boundary (`request.body.*` → `ANY`), untyped parameters, and any plain-JS
  value without annotation — which R08 already measured as the dominant real
  situation (tarkov: 0 failure-capable union hints in 2,207 lines).
- `DYNAMIC_TYPE_HINTS`, which carried Signal B for R07, is **empty on almost
  every comparison operand here** — it populates for return values, not for
  comparison operands generally.

So the anticipated result ("operator recovery works, security-use works, but
operand domains are UNKNOWN on most real JS") is **confirmed for the general
case** — with the sharper CVE-specific finding above layered on top.

---

## What this means for Family B

Family B is **not viable as a declared-type-domain rule**, on two independent
grounds:

1. **Coverage** — one side is `ANY` in the realistic cases (D, E, F), so the
   rule abstains exactly where real code lives.
2. **Soundness direction** — for the one confirmed CVE, better declared-type
   evidence pushes the classification *toward* `NONCOERCIVE`, i.e. away from
   the truth. A rule that improves with more type information but gets the
   known positive more wrong is not a rule worth promoting.

Detecting the actual CVE requires modelling **prototype-chain reachability** —
that `obj[attackerKey]` can yield an inherited `Object.prototype` value
regardless of the declared index signature. That is a *different* capability
from value-domain inference, and it is closer to CWE-1321 (prototype
pollution / prototype property access) than to coercion semantics. The
advisory itself lists CWE-1321 alongside CWE-843, which is consistent with
this reading.

---

## Next milestone (nominated only — not implemented)

Two candidates, and the honest recommendation is the first:

**JS-STATE-R12 — Value-Domain Inference Layer (characterization).** The
general capability, not the bug class. R11 showed domain evidence is real but
patchy; a genuine domain-inference layer (literal propagation, producer
history, index-signature bases, boundary-`ANY` marking) would serve far more
than Family B: coercive comparisons, numeric conversions, truthiness, property
keys, serialization, API argument modelling. This is the substantial general
capability the evidence keeps pointing at.

**Alternative — JS-STATE-R12b — Prototype-Reachability Characterization**, if
the goal is specifically to detect the confirmed CVE. Narrower, directly
targets `obj[userControlledKey]` yielding inherited properties, and would
detect the real bug. But it is a different bug family again (CWE-1321), and
adopting it means accepting that Family B as originally conceived
(coercion-domain reasoning) does not survive contact with its own positive
anchor.

**Family B status: `BLOCKED_ON_DOMAIN_EVIDENCE`** — not rejected, but no
longer the strongest candidate. Family A remains
`SUPPORTED_LOW_BASE_RATE`. Neither should be promoted on current evidence.

---

## Thesis-relevant conclusion

R09 → R10 → R11 form a chain worth stating together:

> A bug family can be blocked at three successive layers, and each blocker is
> invisible from the layer above. R09 found the *frontend* collapsed the
> operator. R10 found that loss was recoverable positionally, moving the
> blocker down to evidence. R11 found the evidence itself is either absent
> (`ANY`) or — for the one confirmed real vulnerability — **present and
> pointing the wrong way**, because the exploit's mechanism is precisely a
> runtime value escaping the declared type that the evidence reports.

The generalizable lesson:

> **Declared-type evidence is unsound for vulnerability classes whose
> mechanism is the violation of declared types.** Static type information
> describes intent; these bugs are the gap between intent and runtime
> semantics. Using the former to reason about the latter will systematically
> classify the most dangerous cases as safe.
