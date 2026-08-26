# JS-PROV-R27 — Gate Assertion-Key Audit

Follow-up to JS-PROV-R26, which found a gate reporting a resolver contradiction
that did not exist because its lookup key was not unique. That is a defect
**class**, not an incident. This audits every gate for it.

## Method

For each gate, extract the expression used to key `est` / `by` / `ab` lookups,
then measure key cardinality against distinct-key cardinality — first on the
gate's own fixture, then on the real corpora.

## Findings

| Gate | Assertion key | Unique on its fixture | Collides on real corpora |
|---|---|---|---|
| js-prov-r08 | callee short name | YES (5/5) | — |
| js-prov-r09 | declaring-method short name | YES (1/1) | — |
| js-prov-r14 | **call code string** | YES (3/3) | **YES** — `validate(schema)` ×9, `Joi.string()` … (45 keys → 32 distinct; abstentions 158 → 102) |
| js-prov-r21 | (method short name, param name) | YES (11/11) | **YES** — `('delete','params')` (20 → 19) |
| js-prov-r23b | local binding name | YES (fixed in R26) | — |
| gate24-ts2, source-r02, poly-r01 | node/record **id** | YES | structurally safe |

**No gate is currently wrong.** Every gate keys uniquely *on its own fixture*,
so all assertions check the record they intend to. But four gates key on
attributes that are **not unique in general** and demonstrably collide on
production code. They are correct by luck of fixture content, not by
construction — precisely R26's situation before the collision appeared.

`js-prov-r14` is the sharpest: it keys on the **call code string**. R13 already
established that code strings are not identities; the gate was doing what the
engine is forbidden from doing.

## A false positive I nearly filed

The first audit run reported `js-prov-r08` colliding on its own fixture
(`installReal`, `installBoth` ×2, 10 keys → 8 distinct). That was **my audit
harness**, which copied `fixture/*.ts` *and* `fixture/*.js`, while the gate's
`run.sh` copies only `t.ts`. Re-running with exactly what `run.sh` copies gave
5/5 unique.

Worth recording because it is the same error class inverted: R26 was a coarse
key manufacturing an apparent *resolver* defect; this was a coarse harness
manufacturing an apparent *gate* defect. In both cases the measurement
apparatus, not the subject, was at fault.

It did surface a real (minor) issue: `js-prov-r08/fixture/gate.js` was a stray
file `run.sh` never copies — dead fixture input, now removed under the
fixture-directory rule.

## Remediation

`R26-FIXTURE-INTEGRITY` added as a permanent tooth to all four
coarse-keyed gates. Each now asserts its own assertion keys are distinct, so a
future fixture addition **fails loudly** instead of silently overwriting a
lookup entry and checking the wrong record.

```text
JS_PROV_R08=13/13   (was 12/12)
JS_PROV_R09=12/12   (was 11/11)
JS_PROV_R14=10/10   (was  9/9)
JS_PROV_R21=13/13   (was 12/12)
JS_PROV_R12=28/28   JS_PROV_R17=18/18   JS_PROV_R23B=33/33
JS_STATE_R07=31/31  PROMOTION_GATE=PASS (7 promoted facts)
```

Keys were **not** changed to ids. Rekeying is a larger change with its own
regression risk, and the audit shows it is not currently needed — the tooth
converts a silent failure mode into a loud one, which is the property that was
missing.

# JS-PROV-R27 VERDICT

```text
DEFECT CLASS:        gate assertions keyed on a non-unique attribute
GATES AUDITED:       all
CURRENTLY WRONG:     0
CORRECT-BY-LUCK:     4 (r08, r09, r14, r21) -- unique on fixture, colliding on
                     real corpora
REMEDIATION:         R26-FIXTURE-INTEGRITY tooth added to all four; stray dead
                     fixture file removed
SUITE:               all gates green; promotion gate PASS
RESIDUAL:            r14 keys on call code strings, which R13 forbids the engine
                     from treating as identities. The tooth makes a collision
                     loud, but rekeying r14 to call ids remains open.
```

## Discipline note

R26's lesson generalized further than expected: four more gates had the same
latent defect, all passing, none wrong. "Passing" and "correct by construction"
are different properties, and a green suite cannot distinguish them.

The near-miss is the more instructive half. Having just been burned by a coarse
key, the reflex on seeing `installReal` twice was to believe it — the finding
confirmed a pattern I had just established. Checking what `run.sh` actually
copies took one command and turned a would-be finding into an artifact of my own
tooling.
