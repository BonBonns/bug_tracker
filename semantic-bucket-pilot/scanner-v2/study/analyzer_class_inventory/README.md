# Repository-wide analyzer class inventory — normalized data model (v2)

This is the authoritative document for this study. It corrects a real category error in
`ANALYZER_CLASS_INVENTORY.md` (kept in place for its research narrative, marked superseded at
the top): that document mixed four different units of account into single lists and totals —

1. **security properties** (a distinct vulnerability class with its own attacker-observable
   consequence — e.g. `OOB_WRITE`, `SSRF`);
2. **implementations/revisions** (a specific file or file+config implementing, or attempting to
   implement, one property — e.g. `oob_index_write_verdict.py` implements `OOB_WRITE`; `R01`
   through `R05` are five successive implementations/revisions of `FALLIBLE_BOUNDED_RESOURCE`);
3. **configuration variants** (a `property_configs/*.json` parameterization of the shared
   `adjudicate_js.py` taint engine — these are configuration, not separate code, and were being
   silently treated as full implementations in places);
4. **infrastructure** (fact exporters, cross-language linkers, adjudication/triage layers,
   capacity models — real, load-bearing, but not themselves security properties).

Concretely, this caused two real errors, both direct results of collapsing these units:

- **`single_object_pass.py` being unsound was never actually double-counted against `OOB_WRITE`
  in the prior document's own bottom-line "22 promotable"** (re-checked directly: `OOB_WRITE`
  was not on that document's own "not promotable" list) — but the prior document provided no
  structural guarantee of that, and a reader auditing it had no way to confirm it without
  re-deriving the same reasoning by hand. This version makes it a mechanical, checkable fact:
  `OOB_WRITE` has 12 implementation rows, 11 `SOUND` and 1 `UNSOUND`
  (`single_object_pass.py`), and the property-level rollup rule (`>=1 SOUND implementation ⇒
  promotable`) is a few lines of code in `compute_totals.py`, not a claim to take on faith.
- **Gate-39 state-provenance infrastructure *was* counted as one of the prior document's "3
  explicitly not promotable" properties** — a real error, since it is infrastructure (own
  README: "NOT REPRODUCIBLE / NOT RUN"), not a security property with its own attacker
  consequence, and has no property it implements. It has been moved to `data/infrastructure.csv`
  and removed from the property universe entirely. The WordPress finding adjudicator was under
  the same risk (it could easily have been miscounted as a 7th WordPress property) and is
  likewise recorded only in `infrastructure.csv`, linked to the 6 real WordPress properties it
  triages rather than counted as one itself.

One substantive, disclosed reclassification changes a total from the prior document: the former
single **`THREAD_SAFETY`** "property" bundled two structurally distinct bugs — `LOCK_BALANCE`
(an existing lock, incompletely released) and `PROTECTED_FIELD` (no lock at all guarding shared
state) — under one umbrella. These have different attacker-observable consequences, different
verdict files, and independent gates (11/11 each). They are split into two properties here. This
is exactly the kind of unit confusion the correction targets, so it is called out explicitly
rather than folded in silently: **this is why the implemented-property total changes from 25 to
26**, not an arithmetic error in either count.

## Data model

Five CSV tables in `data/`, loaded and cross-checked by `compute_totals.py`:

| Table | Grain | Key columns |
|---|---|---|
| `properties.csv` | one row per distinct security property | `property_id`, `ecosystem`, `npm_applicable` |
| `implementations.csv` | one row per (property, file) implementation/revision | `property_id` (FK), `file_path`, `status` ∈ {`SOUND`, `UNSOUND`, `UNVERIFIED`} |
| `infrastructure.csv` | one row per infra component — **never counted as a property** | `feeds_property_ids` (FK list, may be empty) |
| `pipeline_invocations.csv` | one row per (property, pipeline) actually invoked | `property_id` (FK), `pipeline_name`, `packages_processed` |
| `historical_runs.csv` | one row per (property, run) executed outside the stopped pipeline | `property_id` (FK), `status` ∈ {`COMPLETE`, `INCOMPLETE_ABANDONED`} |

`status` on an implementation is a per-file soundness judgment; a property's own promotability is
a **rollup rule**, not a stored field: `SOUND` if any implementation is `SOUND`; `UNVERIFIED` if
none is `SOUND` but none is confirmed `UNSOUND` either (no gate evidence found, not explicitly
rejected — e.g. `WPACL`: "research-grade, hand-tuned... no dedicated gate dir found"); otherwise
`UNSOUND`. This rollup is what makes the `single_object_pass.py`/`OOB_WRITE` case resolve
correctly without hand-reasoning.

`compute_totals.py` also checks referential integrity (every `property_id` referenced from the
other four tables must exist in `properties.csv`) before printing anything, and exits non-zero on
a violation — the totals below cannot silently drift from the underlying rows.

**Scope note, consistent with the read-only instruction**: `compute_totals.py` reads and
aggregates this study's own CSV tables (data *about* already-existing, already-documented
scanner/gate/study artifacts). It does not invoke, import, or execute any scanner, contract,
exporter, or pipeline file itself.

## Computed totals (reproduce with `python3 compute_totals.py`)

```
1. Implemented properties (rows in properties.csv):            26
   (of which have >=1 implementation row in implementations.csv: 26)

2. Promotable properties (>=1 SOUND implementation):            20
   DENYLIST_PATTERN_BYPASS, FAIL_OPEN_SECURITY_CONTROL, FALLIBLE_BOUNDED_RESOURCE,
   GLOBAL_SINGLETON_MUTATION, GUARD_FALLTHROUGH, LLM_INSECURE_OUTPUT_HANDLING,
   LLM_PROMPT_INJECTION, LOCK_BALANCE, MALICIOUS_NPM_INSTALL_EXFIL, NOSQLI, OOB_COMPARE,
   OOB_READ, OOB_WRITE, PROTECTED_FIELD, REDOS, SSRF, UNGUARDED_SERIALIZE_DOS,
   VALIDATION_BYPASS, WP_SQLI, WP_XSS

   UNVERIFIED (no SOUND impl, none explicitly UNSOUND either):   5
   PATH_TRAVERSAL, WPACL, WPCSRF, WPIDOR, WPOPT

   NOT promotable (every implementation UNSOUND):                1
   COMMAND_INJECTION

3. npm-applicable properties:                                   20 of 26
   Excluded: WPACL, WPCSRF, WPIDOR, WPOPT, WP_SQLI, WP_XSS  (PHP/WordPress only)

4. Implementation rows (property x file mappings):              45
   Distinct implementation files:                                44
   Shared across multiple properties: llm_input_verdict.py
     (LLM_INSECURE_OUTPUT_HANDLING, LLM_PROMPT_INJECTION)

5. Infrastructure components (not counted as properties):       11
   link_napi_facts.py, export_c_cpp_facts_v03.sc, export_neutral.sc, adjudicate_oob.py,
   WordPress finding adjudicator, nss-sslmac-capacity-r01, Gate-39 state-provenance,
   moz-scan-hmacct-dynamic-validation, moz-scan-nss-tls13-aead-iv-hardening.patch,
   moz-scan-paired-cve-validation-round1.md, docs/moz-oob-r01/

6. Properties executed by the stopped 494-package pipeline:     1
   FALLIBLE_BOUNDED_RESOURCE

7. Properties executed by any OTHER historical corpus run:      10
   FALLIBLE_BOUNDED_RESOURCE, GUARD_FALLTHROUGH, LLM_INSECURE_OUTPUT_HANDLING,
   LLM_PROMPT_INJECTION, LOCK_BALANCE, MALICIOUS_NPM_INSTALL_EXFIL, OOB_WRITE,
   PROTECTED_FIELD, REDOS, UNGUARDED_SERIALIZE_DOS
   Attempted but INCOMPLETE/ABANDONED (not counted above): NOSQLI (Stage3 corpus-scale
     sweep, ~40-45% timeout rate, known unfixed AJV-schema classifier gap)

   Overlap between #6 and #7 (evaluated by both):                 1  (FALLIBLE_BOUNDED_RESOURCE)
   Properties with NO corpus-scale run evidence found (any kind): 15
```

## What changed from the superseded totals, and why

| Metric | Superseded | Corrected | Why it moved |
|---|---:|---:|---|
| Implemented properties | 25 | **26** | `THREAD_SAFETY` split into `LOCK_BALANCE` + `PROTECTED_FIELD` (two distinct attacker-observable bugs, not one umbrella) |
| Promotable properties | 22 | **20** | Not a regression — a precision gain. The superseded "22" already correctly did not count `single_object_pass.py`'s unsoundness against `OOB_WRITE`, but it also incorrectly subtracted Gate-39 (infrastructure, not a property) as one of "3 not promotable." Once Gate-39 is removed from the property universe and a genuine third state (`UNVERIFIED`) is introduced for the 5 properties with no confirmed gate evidence either way (`WPACL`/`WPCSRF`/`WPIDOR`/`WPOPT`/`PATH_TRAVERSAL` — previously silently folded into "promotable" without disclosing the missing evidence), the honestly-provable "SOUND" count is 20, with 5 more `UNVERIFIED` (not confirmed either way) and 1 genuinely `UNSOUND` (`COMMAND_INJECTION`) |
| npm-applicable properties | 20 of 25 | **20 of 26** | Unchanged numerator — confirms the reclassification above didn't touch npm-applicability; only the denominator moved |
| Evidence-sufficient-to-run-today | ~13 of 24 non-PHP | *(not recomputed this pass — carries a units problem of its own, "evidence bundle sufficiency" is a property-vs-infrastructure judgment that needs the same table treatment; flagged, not re-derived here to avoid asserting a new unverified number)* | |
| Executed by stopped pipeline | 1 | **1 (unchanged)** | The strongest conclusion was never in question — re-derived mechanically here, not just re-asserted |
| Executed by any other historical run | *(not previously reported as a distinct metric)* | **10** | New table (`historical_runs.csv`), requested explicitly — separates real completed non-fixture corpus-scale runs from self-reported gate-fixture-only passes (which are not counted here) and from the one attempted-but-abandoned case (`NOSQLI` Stage3) |

## The strongest conclusion, re-derived rather than re-asserted

**The stopped 494-package npm pipeline evaluated exactly 1 of 26 implemented properties
(`FALLIBLE_BOUNDED_RESOURCE`, via its R04+R05 stages only).** This number does not move under
the correction — it was already a clean single-table fact
(`pipeline_invocations.csv`, one row) and remains 1. What the correction adds is precision
around everything *around* that fact: 20 of the 26 properties are npm-applicable and could in
principle run against this same corpus; 10 properties (including `FALLIBLE_BOUNDED_RESOURCE`
itself, via a separate, earlier, pre-header-fix pass and the independent Nan-capability
real-package runs) have real completed evidence from historical runs *other than* the stopped
pipeline; 15 properties have no corpus-scale run evidence of any kind in this repository today.

No scanner, contract, exporter, gate, or pipeline file was modified or run to produce this
correction — only this study's own CSV tables and the `compute_totals.py` script that reads
them, per the standing read-only instruction.
