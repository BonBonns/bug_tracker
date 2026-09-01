# The real, missing affirmative-applicability step -- defined, built, applied, and its own
# first 5 real promotions manually validated

Per direct instruction: define `applicability_status` separately per property family, add the
required controls, keep task #32 partially open (transitive reachability implemented; callback/
worker and module-load stay diagnostic heuristics), and manually validate the five transitive
promotions -- "the only real records that have crossed the newly completed native-reachability
path" -- before any further scanning.

## Why this was the last remaining structural blocker

The five transitive promotions (task #32 reopened) proved: provenance resolves; the native
candidate is reachable from a registered export; the reachability gate works. Reportability
still failed solely because nothing in this pipeline had ever affirmatively set
`applicability_status = "APPLICABLE"` for a real corpus finding -- task #41's own docstring had
already disclosed this exact gap. `applicability_gate.py` is that step.

## Definitions, per property family (never a single blanket rule)

**Resource Guard (R04/R05/R06)** -- retains R06's own real build-configuration and source-
boundary requirements, adds nothing new:
1. `verdict == "VALUE_ACQUISITION_GUARD_MISSING"` -- confirmed directly in
   `resource_guard_verdict_r06.py`: reaching this verdict at all already REQUIRES
   `exc_config == "disabled"` (every other value returns `CONTRACT_NOT_APPLICABLE`/
   `BUILD_CONFIGURATION_CONFLICT`/`BUILD_CONFIGURATION_UNRESOLVED` first) -- the build-
   configuration requirement is retained by this one condition alone.
2. `provenance.resolved is True`.
3. `source_boundary_evidence` is present -- R04/R05's own legacy findings never carry this key
   (they predate R06's gate); only R06's own real trace produces it.
4. `source_boundary_evidence["traced_to_parameter"]` is a real, named VALUE parameter, not
   `"this"` -- a trace to the implicit receiver/self pointer is not the same "a value parameter
   could plausibly carry JS-supplied data" claim R06's own motivating case (node-libcurl's real
   `size_t size`) is about. Real, disclosed consequence, confirmed against this replay's own
   data: node-libcurl traces to `"size"` and clears this; all 4 of pqclean's own real findings
   trace to `"this"` and do not.

**LOCK_BALANCE / PROTECTED_FIELD** -- determined (real evidence, not assumed) that no property-
specific condition beyond candidate-ness + reachability is needed: `provenance.
PROPERTY_CANDIDATE_RULES`'s own comment already confirms every item these two keys' own
findings lists ever contain is already a real candidate (abstentions only ever increment a
separate counter, never enter the list); `lock_balance_verdict.py`/`protected_field_verdict.py`
were checked directly -- neither has more than the one real `findings.append(...)` site their
own positive fixtures already exercise. Same rule as OOB_*, below.

**OOB_WRITE / OOB_INDEX_WRITE / OOB_READ** -- per direct instruction: the scanner's real
candidate condition, resolved provenance, allowed reachability, and enabled property status.
This makes the record eligible for manual review only -- it does not declare an OOB
vulnerability.

**All five staged properties, one shared rule:**
1. `scanner_candidate is True`.
2. `provenance.resolved is True`.
3. `reachability_status` is in `staged_enablement.py`'s OWN `_EXTERNALLY_REACHABLE_TIERS`
   allowlist (imported directly, never redefined -- a second copy would be a real drift risk).
4. the property's own key is in `staged_enablement.ENABLED_PROPERTIES`.

**OOB_COMPARE** -- not touched at all. Excluded from `applicability_gate.py`'s own
`STAGED_APPLICABILITY_KEYS` explicitly (belt-and-braces, not merely relying on the downstream
`ENABLED_PROPERTIES` veto).

## Controls (`check_applicability_gate.py`, 23/23)

1. **A real eligible staged candidate becomes APPLICABLE and reportable** -- `@eliyya/sange`'s
   real `lock` finding (task #32's own transitive tier), reused from task #34's real replay
   evidence: becomes `APPLICABLE` and `reportable=True` -- the first real, non-synthetic
   `reportable=True` this pipeline has ever produced on real corpus data.
2. **Internal/unregistered, unresolved, disabled, ambiguous, and false-adjudicated records
   remain blocked** -- five separate real/synthetic controls, one per case, including an
   end-to-end chain reusing `reachability_tier.py`'s own real ambiguous-call rejection.
3. **Node-libcurl remains non-reportable** -- real smoke test: its R06 copy becomes
   `APPLICABLE` (the real premises DO hold) but stays non-reportable, `CONFIRMED_FALSE_POSITIVE`
   winning; its R05 copy stays `NOT_YET_DETERMINED` (no `source_boundary_evidence` to apply the
   rule to at all, since R05 predates R06's own gate).
4. **The four pqclean candidates remain NOT_YET_DETERMINED until individually adjudicated** --
   real smoke test: all 4 (`traced_to_parameter == "this"`) stay ungranted.

Plus a synthetic Resource Guard positive (no real corpus example exists today where Resource
Guard's own rule alone, independent of node-libcurl's specific adjudication, produces
`reportable=True` -- disclosed as synthetic, not corpus data).

## The five real promotions, manually validated (highest-priority review population, per direct
## instruction, done before any further scanning)

**All 5 are false positives.** Full account: `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md`. Real
published tarballs fetched and read directly for all 3 packages -- nothing inferred from the
scanner's own output alone.

- **`bindRaw` (`@abandonware/bluetooth-hci-socket`), 2 OOB_WRITE candidates**: a real cross-
  variable `sizeof()` match the extent-derivation logic could not statically confirm, but whose
  real numeric sizes (read directly from both type declarations) match exactly -- `_address`
  (`uint8_t[6]`) and `di.bdaddr` (`bdaddr_t`, a real, standard 6-byte Bluetooth address type).
- **`mtx_lock` / `rwlock_rdlock` (`@confluentinc/kafka-javascript`) and `lock`
  (`@eliyya/sange`), 3 LOCK_BALANCE candidates**: a real, structural LOCK_BALANCE scanner-
  design mismatch, confirmed independently on two unrelated real codebases -- all 3 are
  lock-PRIMITIVE-DEFINING wrapper functions (acquire-and-return by architecture, with release
  delegated to a separate function or the caller), not ordinary application functions expected
  to balance lock/unlock within their own body. The real callers on each path correctly balance
  the lock; the primitive itself was never supposed to.

All 5 recorded in `adjudication_registry.py`'s new `KNOWN_STAGED_ADJUDICATIONS` table, exact
match on `(package, version, staged_key, site_identity)` -- `site_id` for OOB_*, `lock_call_id`
for LOCK_BALANCE (never `method_id` alone, which `bindRaw` alone already proves can be shared by
more than one real, distinct finding).

## Final result, this replay

**0 reportable findings, corpus-wide** (`rerun_aggregator_applicability.py`, over
`results/replay_records_v3.jsonl`): 6 real `APPLICABLE` determinations (5 staged + node-libcurl's
own R06 copy), 7 real `CONFIRMED_FALSE_POSITIVE` adjudications (the 5 staged sites +
node-libcurl's R05 and R06 copies both), 4 pqclean candidates left genuinely open. Every
fail-closed invariant re-verified directly against the real output. Full combined gate suite:
ALL PASS (`check_provenance.py` 48/48, `check_oob_reportable_gate.py` 17/17,
`check_vendored_attribution.py` 16/16, `check_reachability_tier.py` 25/25,
`check_staged_enablement.py` 25/25, `check_six_property_aggregator.py` 18/18,
`check_lock_balance.py` 11/11, `check_protected_field.py` 11/11,
`check_adjudication_registry.py` 22/22, `check_applicability_gate.py` 23/23).

## What remains open

- **Task #32 stays partially open**, exactly as instructed: transitive reachability is
  implemented and validated; `CALLBACK_OR_WORKER_HEURISTIC` (124 real candidates) and
  `MODULE_LOAD_EXECUTION_HEURISTIC` (7) remain diagnostic-only, pending their own dedicated
  positive/negative/ambiguity controls -- not built in this round.
- A real, general LOCK_BALANCE detector-precision gap was found (primitive-defining functions
  flagged as if they should self-balance) -- documented as a recommendation in
  `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md`, not fixed here; per direct instruction, this round
  was validation, not a new capability build.
- The 4 pqclean candidates stay genuinely open, pending an individual review of the same rigor
  as this one.
- The remaining 394 packages stay paused. OOB_COMPARE (task #40) stays disabled.

---
*No new scanning. All changes are recomputation over already-preserved evidence
(`results/replay_records_v2.jsonl` -> `results/replay_records_v3.jsonl`) plus real,
individually-reviewed adjudications recorded against real published source.*
