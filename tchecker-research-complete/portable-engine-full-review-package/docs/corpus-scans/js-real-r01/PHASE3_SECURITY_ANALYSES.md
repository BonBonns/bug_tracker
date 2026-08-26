# JS-REAL-R01 — Phase 3: Existing Security Analyses, Run Unchanged

No engine changes were made for this scan. Every module below is exactly the
code verified in JS-STATE-R02..R05, run against the real corpus's exported
facts with zero modification.

## Applicable tracks

This JS/TS pipeline currently has exactly one promoted security-fact family:
**JS-STATE** (failure-state erasure + sink reachability, R02-R05). There is
no separate "sink/source analysis" or "property-flow analysis" track promoted
for JS/TS specifically (those exist for the C++ track — `SINK-R01`,
`SOURCE-R02` — which does not apply to this corpus). `state_facts.py`
(property/keyed-state reads/writes) and `capture_facts.py` (closures) were run
in Phase 2 as frontend-completeness measurements, not as independent security
analyses — neither currently has a security-verdict layer of its own to run.

This is stated plainly rather than silently treating "no other track exists"
as "no other findings exist" — it's a real scope boundary of the current
pipeline, not a result of this scan.

## JS-STATE run

### Raw erasure facts (JS-STATE-R02, `failure_state_facts.py`)

**1 raw candidate**, out of 2,098 control structures and 50,638 calls in the
corpus. `routes/account.ts:1759-1764`, inside `AccountHandler.emailBounceStatus`
(a filter-callback lambda deduping bounce records by
`` `${bounce.email}:${bounce.createdAt}` ``).

### Sink reachability (JS-STATE-R03/R04/R05, `security_sensitive_reachability.py`)

The single candidate's guarded local reaches two calls
(`seen.has(key)`, `seen.add(key)`) on the continue path (neither excluded by
the R04 then-branch check nor the R05 reassignment check). Neither call
matches the example sink profile (`security_sink_profile.py` only lists
`authenticate`). Result: **`security_sensitive_use: UNKNOWN`** — zero
`SENSITIVE` classifications from this corpus.

### Erasure facts reaching profiled sensitive sinks: 0
### Excluded by branch approximation (R04): 0
### Excluded by reassignment approximation (R05): 0
### Remaining candidates (post-reachability, still UNKNOWN): 1
### UNKNOWN/abstained cases: 1 (the only candidate)

## Headline observation

**Zero SENSITIVE findings** on a real, substantial (77,966 LOC, 50,638 calls)
authentication-server corpus is itself informative, but the single raw
candidate is the more important result of this phase: it is very likely a
**false positive from a different root cause than any of R04/R05's already-
disclosed approximations** — the guard here (`seen.has(key)`) is a `Set`
membership check for deduplication, not a failure/error discriminator check
at all, and the "erased" value (`bounce.email`/`bounce.createdAt`, plain
database record fields) never had a success/failure return contract to begin
with. Full adjudication in Phase 4.
