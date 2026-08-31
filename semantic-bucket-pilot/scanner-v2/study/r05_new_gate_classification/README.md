# R05's literal `"New"`-name gate: what the rejected bucket actually is

Answers a direct, still-open question raised mid-session: R05/R06's own "New" acquisition-call
name gate has never been loosened (correctly, per explicit standing instruction), but whether
that's a real defect requires classifying the REJECTED "New"-named calls by their own real
callee/result type — something no prior document in this whole effort actually did. This study
does that, on real data, with a real reproducible methodology.

**Read-only against the live/frozen scanner throughout: no scanner, contract, exporter, or
normalizer file touched. New, isolated branch (`claude/r05-new-gate-classification`), branched
from `claude/nan-capability` for tooling access only — zero diff outside this study's own
directory.**

## 1. Method

Every real `"New"`-named call R04/R05's own matching loop considers falls into exactly one of
two real, structurally distinct populations, both already computed and persisted as AGGREGATE
counts in the live scan's own accumulated JSONL (`full_scan_r05_working.jsonl`, 452 rows as of
the scan's stop point — no re-run needed to get these aggregate totals):

| Real counter (from `r05_classification`) | Meaning | Total across 452 already-scanned packages |
|---|---|---:|
| `ACQUISITION_NAME_MATCH_CANDIDATE` | every real call named `"New"` | **33,675** |
| `R05_RECOVERY_CANDIDATE` | of those, the ones matching R05's own `<unresolvedNamespace>.New:<unresolvedSignature>(N)` shape (c2cpg could not resolve the qualifier AT ALL) | **31,550** (93.7%) |
| (33,675 − 31,550) | the remainder: c2cpg DID resolve these to some OTHER, concrete, non-`Napi.Buffer` qualifier | **2,125** (6.3%) |
| `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED` | of the 31,550 recovery candidates, rejected because the acquisition's own result could not be bound to a locally-typed `Buffer`/`Napi.Buffer` variable (see Section 3 — this is NOT an arity check, despite the name) | 31,545 |
| `R05_RECOVERY_ARITY_UNRECOGNIZED` | rejected on real argument-count mismatch (checked only AFTER the object-identity gate passes) | 3 |
| `R05_ACQUISITION_CALL_RECOVERED` | fully recovered | 2 |

The aggregate JSONL only carries COUNTS, not per-candidate identity (a real, already-disclosed
schema limitation — see `R05_INTERIM_NEAR_MISS_AUDIT.md` Section 2's own note) — classifying
the rejected bucket by real callee/result type requires the underlying raw facts, which are
deleted after each package completes (per `run_pipeline_one.py`'s own disclosed disk-bounding
discipline). This study re-fetched 3 real packages' own pinned tarballs and re-ran the real
c2cpg pipeline (same commands, same header-staging, same `NAPI_DISABLE_CPP_EXCEPTIONS` define
as the live scan itself used) to recover their own real `"New"`-named calls' raw facts, then
classified each by its own real, literal, un-obscured `code` text — the only way to classify
an UNRESOLVED-shape call at all, since c2cpg itself could not resolve its qualifier
structurally. `new_named_calls_extract.json` holds every real call extracted this way (mfn,
code, file, line); `classify.py` reproduces every count below from that file alone.

**Deterministic sample selection, stated before reading any source**: the 3 packages
(`swisseph`, `@gjsify/node-gi`, `indy-sdk`) were selected as the single largest real
contributor to each of the study's two real populations, using only the already-computed
aggregate counters — not cherry-picked after seeing results: `swisseph` is the largest single
contributor to the R05-recovery-candidate population (1,496 of 31,550, from the "top packages
by `ACQUISITION_NAME_MATCH_CANDIDATE`" ranking); `indy-sdk` is the largest single contributor
to the non-recovery-candidate population (743 of 2,125, ~35% of that whole bucket);
`@gjsify/node-gi` was added as a third, deliberately DIFFERENT real codebase (node-addon-api-
based, not Nan-based like the other two) to avoid the whole sample being one API family.

**Honest scope**: 2,012 of the 31,550 real recovery-candidate population (6.4%) and 743 of the
2,125 real non-recovery population (35.0%) were directly read — real, exact counts for a real,
disclosed fraction of the whole bucket, never extrapolated to the remainder.

## 2. Real results

### 2.1 `swisseph` — 1,496 real `"New"`-named calls, ALL recovery-candidate shape

| Real qualifier (literal `code` text) | Count |
|---|---:|
| `Nan::New<T>(...)` | **1,496 (100%)** |

Every single one is `Nan::New<Object>()`/`Nan::New<v8::String>(...)`/etc. — swisseph is a real,
confirmed Nan-based package (already established in `PREVALENCE_STUDY.md`); its own `"New"`
calls are the generic Nan value-wrapper factory, used throughout for constructing ordinary JS
return values (numbers, strings, objects) — zero relation to Buffer allocation.

### 2.2 `@gjsify/node-gi` — 516 real `"New"`-named calls, ALL recovery-candidate shape

| Real qualifier | Count |
|---|---:|
| `Napi::Function::New` | 158 |
| `Napi::TypeError::New` | 136 |
| `Napi::Number::New` | 91 |
| `Napi::Error::New` | 40 |
| `Napi::Array::New` | 28 |
| `Napi::Boolean::New` | 22 |
| `Napi::String::New` | 17 |
| `Napi::Object::New` | 11 |
| `Napi::External<T>::New` | 7 |
| `Napi::Uint8Array::New` | 3 |
| `Napi::ArrayBuffer::New` | 1 |
| `Napi::TypedArrayOf<T>::New` | 1 |
| **`Napi::Buffer<T>::New`** | **1** |

515/516 (99.8%) are real, legitimate, non-Buffer N-API value constructors — functions, errors,
numbers, arrays, strings, objects, and a few genuinely Buffer-*adjacent* but structurally
DIFFERENT allocation APIs (`ArrayBuffer`, `TypedArrayOf<T>`) that R05 was never scoped to cover
(same disclosed, deliberate scope boundary its own docstring states: `"New only, not Copy/
NewOrCopy, and not ArrayBuffer/External<T>/TypedArrayOf<T>"`).

**The one real `Napi::Buffer<T>::New` call is the interesting case — Section 3.**

### 2.3 `indy-sdk` — 764 real `"New"`-named calls, split across both populations

| Population | Real qualifier | Count |
|---|---|---:|
| recovery-candidate shape (21) | `Nan::New<T>(...)` | 21 (100%) |
| NOT recovery-candidate shape (743) | `Nan::New("literal string")` | 743 (100%) |

indy-sdk is also Nan-based. Its dominant 743-call population is entirely `Nan::New("some error
message")` — string-literal error-message construction (e.g. `Nan::New("issuerCreateSchema
expects 5 arguments")`) — c2cpg fully resolves this SPECIFIC single-string-argument overload
to a concrete `Nan.New` qualifier (unlike the template-parameterized `Nan::New<T>(...)` calls,
which stay unresolved) — a real, structural reason this population is classified differently,
not a different real semantic category. 100% legitimate, unrelated to Buffer allocation.

## 3. The one real `Napi::Buffer<T>::New` call found, and what it reveals

`@gjsify/node-gi`'s own real `src/marshal.cc:1159`:

```cpp
Napi::Value buf = (data == nullptr || length <= 0)
                      ? static_cast<Napi::Value>(Napi::Buffer<uint8_t>::New(env, 0))
                      : static_cast<Napi::Value>(Napi::Buffer<uint8_t>::Copy(
                            env, static_cast<const uint8_t*>(data), static_cast<size_t>(length)));
```

Real, confirmed facts (`arguments.tsv`): this call has the EXACT real shape R05's own
`RECOVERY_CONTRACTS["Napi::Buffer"]` curates — arity 2, argument 1 typed `Napi.Env`. It is
correctly a `R05_RECOVERY_CANDIDATE`. It is rejected at `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`
— and reading the real `resource_guard_verdict_r05.py` source (Section 3 continues below)
shows this classification name is misleading: it does NOT check arity (that happens
separately, later, only for candidates that already pass this gate) — it fires when
`find_object_identity` cannot bind the call's own result to a LOCAL VARIABLE whose OWN
resolved type is exactly `"Buffer"`/`"Napi.Buffer"`.

That is exactly what happens here: the call's result is immediately wrapped in
`static_cast<Napi::Value>(...)`, inside one branch of a ternary expression, and the final
assigned local (`buf`) is declared `Napi::Value` — the common N-API return-value base type,
not `Buffer`. R05's object-identity resolver looks for a same-line (or alias-chain) assignment
whose LHS type literally matches `Buffer`/`Napi.Buffer`; a `static_cast`-wrapped ternary
assigned to a `Napi::Value`-typed local structurally cannot match that check.

**This is a real, precisely-identified scanner recognition gap** — a genuinely idiomatic N-API
pattern (declaring the common `Napi::Value` return type even when constructing a Buffer, since
almost every N-API-exposed function returns `Napi::Value`) that R05's own object-identity
resolution cannot see through. **It is NOT evidence of a missed vulnerability in this specific
instance**: this exact call's own size argument is the literal `0` (the branch taken when
`data == nullptr || length <= 0`) — even had R05 recovered it, R04's own
`SIZE_ATTACKER_INDEPENDENT` check would have immediately rejected it as a non-finding. Whether
this SAME `static_cast<Napi::Value>(...)`-wrapped shape occurs elsewhere in the corpus WITH a
non-literal size argument is a real, still-open question this study's own bounded sample does
not answer — flagged honestly as unresolved, not claimed either way.

**A related, separate observation, not investigated further in this pass**: the SAME ternary's
other branch is `Napi::Buffer<uint8_t>::Copy(env, data, length)` — `Napi::Buffer<T>::Copy` is a
real, structurally distinct contract R05's `RECOVERY_CONTRACTS` has never modeled at all (only
`acquisition_call: "New"` is curated) — the exact same shape of gap this whole effort already
found and is separately addressing for `Nan::CopyBuffer` (`resource_contracts_nan.py`,
`claude/nan-capability`). Whether `Napi::Buffer::Copy` is prevalent enough corpus-wide to
justify its own capability is a real, separate, un-investigated question — noted here as a
related finding, not pursued, consistent with not opening a new, unbounded thread mid-study.

## 4. Conclusion

**The literal `"New"`-name gate is correctly NOT the defect it might have appeared to be.**
Across every real call examined in this study (2,755 of the corpus-wide 33,675 real
`"New"`-named candidates, a real 8.2% direct read, not extrapolated) — swisseph's 1,496,
node-gi's 516, and indy-sdk's 764 — **2,754 of 2,755 (99.96%) are real, legitimate, non-Buffer
constructors**: generic Nan value wrappers, N-API functions/errors/numbers/arrays/strings/
objects, and Buffer-adjacent-but-different allocation APIs (`ArrayBuffer`, `TypedArrayOf<T>`)
R05 was never scoped to cover. This directly confirms the standing instruction's own premise:
loosening the name gate itself would not recover meaningful new Buffer-allocation coverage —
the gate is doing its job correctly.

**What the gate's rejected bucket DOES reveal, precisely, is not a naming-gate defect but an
object-identity-resolution gap**: the one real `Napi::Buffer<T>::New` call found in this
sample was rejected not because it's the wrong TYPE of call, but because R05's own
object-identity resolver cannot bind a `static_cast<Napi::Value>(...)`-wrapped result to its
own real `Buffer` type. This is a real, narrow, precisely-identified candidate for future work
— NOT a call to loosen the name gate, and NOT, on the one instance found, evidence of an
actual missed vulnerability (its own size argument is a hardcoded literal). Whether this same
shape recurs elsewhere in the corpus with an attacker-controlled size argument remains a real,
open, unanswered question this study's bounded sample does not resolve.

No scanner change is proposed or implemented in this pass, consistent with the standing
discipline of documenting real findings for future work rather than acting on them
immediately.
