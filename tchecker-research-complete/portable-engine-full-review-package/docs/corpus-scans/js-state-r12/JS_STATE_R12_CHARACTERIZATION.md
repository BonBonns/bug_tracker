# JS-STATE-R12 — Prototype-Reachable Property Read Characterization

**Characterization only. Nothing implemented.** R07 unchanged. No detector, no
verdict, no `PropertyReadFact` built.

Chosen over generic value-domain inference because R11 demonstrated that
better declared-domain evidence does not solve the positive anchor and can
increase confidence in the wrong abstraction. The missing fact is not "what
type is this expression" but:

> Can `base[key]` resolve to an **inherited** property rather than an own
> property, because JavaScript property lookup traverses the prototype chain —
> and can Fable prove when attacker-controlled `key` makes that runtime
> alternative relevant?

The distinction under test:

```text
DECLARED_VALUE_DOMAIN   !=   RUNTIME_LOOKUP_DOMAIN
```

---

## Measured evidence (real Joern run, 9-case fixture)

### Base discrimination — **STRONG**

| Case | Base | `baseType` |
|---|---|---|
| T1/T2/T3/T5/T6/T8/T9 | `users` | `{ [x: __ecma.String]: __ecma.String; }` |
| T4 | `safe` | `Object.create:<returnValue>` |
| T7 | `m` (Map) | `ANY` |

Ordinary object literals and `Object.create(...)` results are **structurally
distinguishable at the base**. This is the discrimination R11's approach
lacked.

### `Object.create(null)` — **PROVABLE**

```text
create arg1 label=LITERAL code=null type=__ecma.Null
```

The null-prototype argument is a literal with `typeFullName = __ecma.Null`.
So `PROTOTYPE_VALUE_BLOCKED` for T4 is provable from **positive evidence**
(the literal `null` argument), not inferred from the callee name alone. Note
the base's type (`Object.create:<returnValue>`) does *not* itself encode the
null prototype — argument inspection is required.

### Map negative control — **EXCLUDED BY CONSTRUCTION**

This is the cleanest result in the milestone. `m.get(input)` never produces an
`<operator>.indexAccess` node at all — it lowers to `<operator>.fieldAccess`
(`.get`) plus a call. So a fact model keyed on `indexAccess`/`fieldAccess`
property reads **cannot** accidentally absorb `Map`'s storage model. The
negative control is satisfied structurally rather than by a name exclusion,
which is materially stronger.

### Key provenance — **PARTIAL, and this is the blocker**

| Case | Key | REF resolves to |
|---|---|---|
| T1 | `"alice"` | LITERAL |
| T2 | `"__proto__"` | LITERAL |
| T3 | `input` | `LOCAL` |
| T4 | `input` | `LOCAL` |
| T5/T6 | `input` | `LOCAL` |
| T8 | `k` | `METHOD_PARAMETER_IN` |
| T9 (CVE) | `username` | `METHOD_PARAMETER_IN` |

Literal vs. non-literal keys separate cleanly. Constant keys can further be
checked against the base's own written properties (`{ alice: "secret" }`), so
`"alice"` is provably own and `"__proto__"` is provably not-own.

**But `KEY_CONTROLLED` is not establishable.** T3 (nominally attacker-selected)
and T8 (explicitly uncontrolled) are *indistinguishable*: both are non-literal
keys resolving through REF to a binding. Proving attacker control requires a
taint-source model that this pipeline does not have for JS/TS — the same gap
JS-REAL-R01 recorded when it found no JS/TS source/sink profile exists.

### Own-property guards — **RECOGNIZABLE, requires a closed-set idiom table**

```text
t5  cond = !Object.prototype.hasOwnProperty.call(users, input)   (call name: "call")
t6  cond = !Object.hasOwn(users, input)                          (call name: "hasOwn")
```

Both appear as control structures with early return, so the existing R04
then-branch machinery (`guard_then_branch_members.tsv`) would establish
"blocked on the surviving path." T6 is clean (`hasOwn` is the callee name);
T5 requires matching the `Object.prototype.hasOwnProperty.call` chain, whose
callee name is the generic `call`. Both are closed-set idiom recognition —
policy, like R07's builtin table — not inference.

---

## Per-case classification

```text
T1 constant own key
  BASE_DECLARED_DOMAIN: STRING (index signature)
  BASE_RUNTIME_PROTOTYPE: Object.prototype     KEY: LITERAL "alice"
  KEY_CONTROLLED: NO      OWN_PROPERTY_PROVEN: YES (in base object literal)
  PROTOTYPE_LOOKUP_POSSIBLE: NO (own property shadows)
  RESULT: OWN_VALUE_ONLY

T2 constant __proto__ key
  KEY: LITERAL "__proto__"   KEY_CONTROLLED: NO
  OWN_PROPERTY_PROVEN: NO (not in base literal)
  PROTOTYPE_LOOKUP_POSSIBLE: YES
  DECLARED_VALUE_DOMAIN: STRING    RUNTIME_VALUE_DOMAIN: STRING | OBJECT
  RESULT: PROTOTYPE_VALUE_POSSIBLE

T3 attacker-selected key
  KEY: IDENTIFIER (LOCAL)    KEY_CONTROLLED: UNKNOWN  <-- not provable
  OWN_PROPERTY_PROVEN: NO    PROTOTYPE_LOOKUP_POSSIBLE: YES
  RESULT: PROTOTYPE_VALUE_POSSIBLE (structural), attacker-control NOT claimed

T4 Object.create(null) base
  BASE_RUNTIME_PROTOTYPE: null (PROVEN: literal null arg to Object.create)
  KEY: IDENTIFIER   PROTOTYPE_LOOKUP_POSSIBLE: NO
  RESULT: PROTOTYPE_VALUE_BLOCKED

T5 hasOwnProperty.call gate
  PROTOTYPE_LOOKUP_POSSIBLE: NO on surviving path (early-return guard)
  RESULT: PROTOTYPE_VALUE_BLOCKED

T6 Object.hasOwn gate
  RESULT: PROTOTYPE_VALUE_BLOCKED

T7 Map.get  <-- NEGATIVE CONTROL
  ACCESS_KIND: not a property read at all (fieldAccess + call, no indexAccess)
  RESULT: OWN_VALUE_ONLY / out-of-model (correctly never enters the fact space)

T8 uncontrolled unknown key
  KEY_CONTROLLED: UNKNOWN (indistinguishable from T3)
  RESULT: PROTOTYPE_VALUE_POSSIBLE (structural), attacker-control NOT claimed

T9 CVE REPLAY
  BASE: users, ordinary object     BASE_RUNTIME_PROTOTYPE: Object.prototype
  KEY: username (METHOD_PARAMETER_IN)   KEY_CONTROLLED: UNKNOWN
  OWN_PROPERTY_PROVEN: NO          PROTOTYPE_LOOKUP_POSSIBLE: YES
  DECLARED_VALUE_DOMAIN: STRING
  RUNTIME_LOOKUP_DOMAIN: STRING | OBJECT (Object.prototype reachable)
  RESULT: PROTOTYPE_VALUE_POSSIBLE
```

---

## The CVE evidence chain, now expressible

R11 could only produce `STRING == ANY -> DOMAIN_UNKNOWN`. R12 supports a
materially richer and more defensible chain:

```text
username  (METHOD_PARAMETER_IN, control UNKNOWN)
        v
dynamic property lookup on an ordinary object (base prototype = Object.prototype)
        v
no own-property guard on this path, key not provably own
        v
PROTOTYPE_VALUE_POSSIBLE  ->  runtime value domain (STRING | OBJECT)
                              EXCEEDS declared domain (STRING)
        v
abstract equality performs coercion   (operator identity per R10)
        v
authentication decision
```

**Every link except one is establishable from current facts.** The single
missing link is `KEY_CONTROLLED` — attacker control of `username`.

This is a decisively better position than R11, where the missing evidence was
not merely absent but *pointed the wrong way*. Here the evidence points
correctly; one component is simply not yet modelled.

---

## Teeth: why this does not degenerate into "`obj[x]` is dangerous"

| Requirement | Satisfied by |
|---|---|
| plain object + constant known-own key -> OWN_VALUE_ONLY | T1, via base object-literal membership |
| plain object + `"__proto__"` -> PROTOTYPE_VALUE_POSSIBLE | T2 |
| plain object + uncontrolled unknown key -> possible, **no control claim** | T8 (and T3 — indistinguishable, honestly reported) |
| `Object.create(null)` + attacker key -> BLOCKED | T4, proven via literal `null` argument |
| hasOwn guard + attacker key -> BLOCKED on surviving path | T5, T6 |
| `Map.get` -> not prototype lookup | T7, excluded structurally (no `indexAccess` node) |

The load-bearing tooth is the third: `PROTOTYPE_VALUE_POSSIBLE` must **never**
by itself imply a security claim, because T3 and T8 are indistinguishable and
T8 is benign by construction.

---

## Next milestone (nominated only — not implemented)

**JS-STATE-R13 — JS/TS Source/Taint Provenance Characterization.**

R12 localized the gap precisely: everything in the CVE chain is establishable
except attacker control of the property key. That is the *same* missing
capability JS-REAL-R01 recorded (no JS/TS source profile exists, only the C++
track has `SOURCE-R02`), now independently re-derived from a different
direction — which is good evidence it is the real next dependency rather than
a convenient one.

Scope should be characterization: can request/IO boundaries
(`request.body.*`, `req.query.*`, `process.argv`, deserialization results) be
established as sources with the same positive-evidence discipline used
throughout — i.e. an explicit, external, curated profile (like
`security_sink_profile.py`), never name inference, with absence recorded as
UNKNOWN rather than "not attacker-controlled"?

Only after that should a `PropertyReadFact` / `PrototypeReachabilityFact`
model be characterized for promotion, with R12's fixture as its permanent
teeth.

**Family statuses unchanged:** A `SUPPORTED_LOW_BASE_RATE`; B
`BLOCKED_ON_DOMAIN_EVIDENCE`. Prototype reachability is tracked as a distinct
family (CWE-1321-shaped), **not** as an extension of B.

---

## Thesis conclusion (R11's statement, corrected)

The prior phrasing overreached. Declared types were not false in R11 — they
correctly described the program's intended index-signature domain. The error
was treating that evidence as an exhaustive account of runtime values.
Corrected:

> **A declared type is positive evidence about intended values, not proof that
> runtime semantics cannot produce values outside that domain.**

And the full R09→R12 arc:

```text
R09  known vulnerability establishes target behavior
 ->  R10  frontend loses == vs ===; structural span recovery restores it
 ->  R11  declared operand domains become available, but richer type evidence
          predicts the SAFE model while runtime prototype semantics produce the bug
 ->  R12  model runtime property-lookup semantics; the chain becomes expressible
          and the residual gap narrows to a single missing fact (key control)
```

Each milestone moved the blocker down one semantic layer, and each blocker was
invisible from the layer above.
