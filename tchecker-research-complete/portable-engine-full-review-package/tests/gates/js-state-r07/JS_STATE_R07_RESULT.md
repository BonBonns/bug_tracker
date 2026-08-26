# JS-STATE-R07 — RETURN-CONTRACT + FAILURE-GUARD PRECONDITION

## Status: IMPLEMENTED, real run, PASS. Exact FxA replay complete.

```text
JS_STATE_R07=31/31
```

Regression chain, all real runs, all clean:

```text
JS_STATE_R02=28/28   (unchanged -- R02 itself was not modified)
JS_STATE_R03=30/30   (unchanged -- includes R04 then-branch and R05
                       reassignment exclusion checks)
GATE24_TS=27/27      (unchanged -- shares export_ts_facts.sc)
JSTS_R05=8/8         (unchanged -- shares export_ts_facts.sc)
CANONICAL_ENGINE_GATE23=25/25  (unchanged -- unrelated Java core, sanity check
                                 that nothing in the broader engine regressed)
```

## What was implemented

Exactly what JS-STATE-R06 demonstrated, nothing broader. A candidate is now
promoted only when all five hold:

1. Existing ERASES fact (JS-STATE-R02, untouched)
2. **Failure-style guard shape** (new: `js_state_r07.py`, SIGNAL A)
3. **Positive union/return-contract evidence** (new: `js_state_r07.py`, SIGNAL B)
4. Guard subject = transformed value (already guaranteed by JS-STATE-R02's
   own REF-based construction -- verified present, not re-implemented)
5. Sensitive sink reachability under current R04/R05 rules (JS-STATE-R03/04/05,
   untouched)

SIGNAL A's closed set is `{<operator>.instanceOf, <operator>.equals,
<operator>.notEquals}` — deliberately narrow. `instanceOf` is what
JS-STATE-R06's fixture itself exercised directly. `equals`/`notEquals` were
added because retaining the null|number case (`id === null`) was an explicit
requirement and R01's original characterization already validated `equals` as
a distinctly-identifiable comparison node using the same REF mechanism as
`instanceOf` — this is disclosed in `js_state_r07.py`'s docstring as a
deliberate inclusion, not silent scope creep. Relational operators and any
named method call (`.has()`, `.includes()`, custom predicates) remain
explicitly excluded, per instruction.

SIGNAL B reads `type_hints.tsv`'s `dynamicTypeHintFullName` at the erasing
transformation's own argument node(s) — the exact mechanism JS-STATE-R06
found. Three-way, asymmetric, as specified:
- Union present with a failure-capable branch (closed marker set: `error`,
  `null`, `undefined`, `exception`, `failure`, case-insensitive substring) ->
  `ESTABLISHED`.
- Union present, no failure-capable branch -> `NOT_UNION`.
- No hint recorded at all -> `UNKNOWN`.

Only `ESTABLISHED` satisfies the positive-evidence requirement to emit.
`UNKNOWN` is recorded distinctly from `NOT_UNION` in every fact's audit
trail and never silently collapsed into either "safe" or "candidate" — per
instruction, missing type hints are not turned into `SAFE`.

## Permanent fixture: the four-way isolation matrix + null|number retention

`tests/gates/js-state-r07/fixture/r07_fixture.ts`, five cases, all real
Joern runs, all producing the exact predicted result:

| Case | Guard shape (A) | Return contract (B) | Sink | R07 EMIT |
|---|---|---|---|---|
| `truePositive_unionReturnInstanceofGuard` | `instanceOf` (yes) | `ESTABLISHED` | SENSITIVE | **YES** |
| `<lambda>0` (FxA-shaped false positive) | `has` (no) | `UNKNOWN` | UNKNOWN | no |
| `isolation_guardShapeOnlyNoReturnContract` | `instanceOf` (yes) | `UNKNOWN` | SENSITIVE | no |
| `isolation_returnContractOnlyNonComparisonGuard` | `has` (no) | `ESTABLISHED` | SENSITIVE | no |
| `nullNumber_survivesMalformedReturnType` | `equals` (yes) | `ESTABLISHED` | SENSITIVE | **YES** |

One fixture fix made relative to R06's original: `isolation_returnContract
OnlyNonComparisonGuard` originally passed a *fresh* `Number(r)` call to
`authenticate()`, not the guarded local `key` itself — meaning under the base
R02/R03 pipeline, `key` never reached a sensitive sink at all, so its
exclusion would have been confounded (excluded because it never reached a
sink, not because of guard shape). Fixed so `key` itself reaches
`authenticate()`, making its `SENSITIVE` sink status confirmed and its R07
exclusion attributable to guard-shape alone, cleanly isolating what this row
is meant to test.

## The exact FxA replay

Same commit (`e856cffdbf261c0b73ff51cde86045f77d26044b`), same scoped
directories (`packages/fxa-auth-server/lib/{routes,tokens,crypto,oauth}`),
same frontend output — the raw exported facts from JS-REAL-R01's original run
were reused directly (not regenerated), since `export_ts_facts.sc` has not
changed since that run. This is the strictest possible replay: even frontend
run-to-run nondeterminism is eliminated as a variable.

### BEFORE R07 (JS-REAL-R01, unchanged)

```text
raw erasure candidates:  1
sensitive candidates:    0
false positives:         1
true candidates:         0
```

### AFTER R07

```text
contract-established:      0  (the one raw candidate's return_contract is UNKNOWN, not ESTABLISHED)
guard-shape-established:   0  (its guard is `has`, not in the closed set)
both-established:          0
sensitive candidates:      0  (unchanged -- was already 0)
false positives:           0  (the one false positive is now excluded, not just uncounted)
true candidates:           0  (unchanged -- there were none to begin with)
```

### The specific verification requested

```text
bounce.email / template coercion (mozilla/fxa routes/account.ts:1759,
inside AccountHandler.emailBounceStatus's dedup filter callback):

RETURN CONTRACT: NOT ESTABLISHED  (r07_return_contract = "UNKNOWN" --
    template-string coercion's arguments are `bounce.email`/`bounce.createdAt`,
    field-access expressions with no dynamicTypeHintFullName recorded at all,
    exactly the blind spot JS-STATE-R06 flagged and explicitly declined to
    paper over)
FAILURE GUARD: NOT ESTABLISHED  (r07_guard_operator = "has" -- seen.has(key)
    is a Set-membership method call, not a member of the closed
    instanceOf/equals/notEquals comparison set)
-> excluded (r07_emit = false)
```

**This is not "1 -> 0" by coincidence or by an overly blunt filter.** Both
signals independently and correctly identify the exact mechanism
JS-REAL-R01's Phase 4 adjudication already established by hand
(`RETURN_CONTRACT_NOT_ESTABLISHED`): the guard is not failure-shaped, and the
coerced value's origin was never shown to carry a failure state. The
`UNKNOWN` classification for return-contract is preserved and visible in the
audit trail — it is not silently reported as `NOT_UNION` (a stronger, unearned
claim) or folded into a bare "excluded" with no reason recorded.

## Conclusion

The initial JS-STATE formulation (R02 alone) was too permissive: a guard
condition containing a reference to an erasing-transformation's result was
sufficient to flag a candidate, regardless of what kind of comparison the
guard used or whether the transformed value's origin ever established a
failure-carrying contract. Requiring independently demonstrated
failure-contract and failure-guard evidence (R07) eliminated the only
observed real-corpus false positive, for the exact, disclosed reason
JS-REAL-R01's manual adjudication already found — not a different or
coincidental one.

**This is explicitly not read as "R07 works" in any general sense.** Per
instruction: one corpus reaching zero surviving findings does not tell us
whether R07 is precise or simply too restrictive. JS-STATE's raw candidate
rate on this corpus was already near zero before R07 (1 / 50,638 calls); R07
can only ever reduce that further, never increase it. Whether R07's added
preconditions are cutting real recall (excluding genuine bugs that don't
happen to use `instanceof`/`equals` or a directly-hinted union type) remains
completely untested by this corpus, because this corpus never had more than
one candidate to test discrimination against in the first place.

## Next: a second, independent corpus

Per instruction, JS-STATE is not being touched further based on this single
result. The next step is scanning a second, unrelated JS/TS application
corpus with the exact R02→R03→R07 pipeline (no further engine changes),
specifically to get the first real signal on whether R07 generalizes or is
simply narrow enough to always find nothing. A second corpus landing at zero
candidates again would be a meaningfully different (weaker) result than this
one reaching zero, and should be reported as such rather than treated as
confirmation.
