# The real, missing affirmative-applicability step -- defined, built, applied, and its own
# first 5 real promotions manually validated

## CORRECTIONS (applied after this round was first written -- read this before anything below)

Two corrections, per direct instruction, both real and already fixed (not merely documented):

1. **Scope-language error.** "0 reportable findings, corpus-wide" (below) is WRONG. This round
   was the 97-bundle replay from the frozen 100-package diagnostic sample, never a corpus-wide
   run. The accurate statement: **zero reportable findings among 97 successfully replayed
   packages from the frozen 100-package diagnostic sample; 394 eligible packages were not
   evaluated by this replay.**

2. **A real node-libcurl applicability regression, now fixed at its root cause.** All 6
   `APPLICABLE` determinations this round were checked, per direct instruction. One of them WAS
   node-libcurl's own R06 `ReadFunction` finding -- the "SMOKE #3: ... the real premises DO
   hold" line below is **retracted; the premises did NOT hold.** Root cause:
   `npm_corpus/npm_build_configuration.tsv`'s node-libcurl row was itself STALE -- it recorded
   `exception_configuration: disabled`, predating `extract_build_config.py`'s own real fixes
   (gyp `!`-list-removal polarity; `node_addon_api_except` gyp-target dependency evidence). Live
   re-verification against the real published tarball, and independent reruns of both
   `resource_guard_verdict_r05.py` and `resource_guard_verdict_r06.py` against this real site
   under the corrected value, all agree: the real, current, live-reproducible value is
   **`enabled`**. Under `enabled`, node-libcurl's real Easy::ReadFunction verdict is
   `CONTRACT_NOT_APPLICABLE`, not `VALUE_ACQUISITION_GUARD_MISSING` -- `scanner_candidate`
   becomes `False`, and it never even reaches `applicability_gate.py`'s own condition 1. The
   earlier, independently-established real evidence (exceptions enabled for node-libcurl's
   actual build target; allocation failure throws and is caught; source boundary
   unresolved/libcurl-supplied size -- see `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`) is exactly
   what this correction restores; the pipeline's own stale data had drifted away from it.

   **Fixed, not just documented:** `npm_corpus/npm_build_configuration.tsv`'s node-libcurl row
   corrected in place (citing the live re-verification); `study/task34_replay/
   fix_libcurl_build_config_regression.py` reruns R05+R06 against node-libcurl's preserved
   `cpp_raw` under the corrected build config and produces `results/replay_records_v4.jsonl`
   (v3 plus this one targeted correction -- no Joern rebuild, no new download beyond reusing
   already-resolved provenance); `check_provenance.py`'s own central regression test (a REAL,
   live, fresh pipeline rerun, not synthetic) and `check_applicability_gate.py`'s SMOKE #3 were
   both updated to assert the corrected reality and to add **the specific invariant required**:
   with `adjudication_status` stripped entirely (simulating "this site was never reviewed"),
   node-libcurl's real R05 and R06 findings both still fail to become reportable, purely because
   the corrected verdict makes `scanner_candidate=False` / `applicability_gate.py`'s own
   condition 1 fail -- proving `adjudication_registry.py`'s real, separately-cited adjudication
   is now a genuine SECOND, independent veto, never the only thing masking an incorrect
   applicability grant. Full gate suite reran clean after the fix (see the bottom of this doc).

   **Two systemic precision gaps, opened as structural follow-ups, required before expanding to
   the remaining 394 packages** (their own regressions kept exactly as-is): LOCK_BALANCE needs
   structural recognition of lock-primitive wrapper definitions (`mtx_lock`/`rwlock_rdlock`/
   `Mutex::lock`-shaped functions), and OOB analysis needs type/extent equivalence reasoning
   (e.g. `uint8_t[6]` vs. a 6-byte destination type like `bdaddr_t`) -- see "Recommendation" in
   `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md` and the "What remains open" section at the bottom of
   this document. Callback/worker (124 candidates) and module-load (7) reachability also remain
   unfinished under task #32, unchanged by this correction.

   **Now audited, closed -- see "Build-configuration staleness audit" below.** The disclosed risk
   that other packages' `npm_build_configuration.tsv` rows might be similarly stale was real: 32
   of the other 96 successfully-replayed packages' rows WERE stale by the same class of defect.
   None of the 32 affected any actual R06 finding (none of them had any R06 finding at all, at
   any build-config value) -- node-libcurl remains the only package in this 97-package sample
   where stale build-config data produced an incorrect candidate. Fixed at the data layer for all
   32 regardless, and reconfirmed via a targeted rerun for each. Full account, per-package
   breakdown, and the reconfirmed final funnel are in the dedicated section below.

3. **Wording nit.** "Corpus-wide APPLICABLE count" (used loosely in chat, never committed to this
   document) should read "97-package replay APPLICABLE count" -- this document's own "Final
   result" section already used the correctly-scoped wording throughout; noted here only so the
   correction is on the record.

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
3. **Node-libcurl remains non-reportable** -- ~~real smoke test: its R06 copy becomes
   `APPLICABLE` (the real premises DO hold) but stays non-reportable, `CONFIRMED_FALSE_POSITIVE`
   winning~~ **CORRECTED (see "CORRECTIONS" at the top of this document): this was itself a real
   applicability regression caused by a stale `npm_build_configuration.tsv` row. Fixed at its
   root cause -- under the corrected build config, node-libcurl's R06 copy never becomes
   `APPLICABLE` at all (`scanner_candidate=False`, verdict `CONTRACT_NOT_APPLICABLE`); it stays
   non-reportable for the RIGHT reason, with `CONFIRMED_FALSE_POSITIVE` adjudication now a real,
   independently-cited second veto, not the only thing preventing an incorrect grant.** Its R05
   copy stays `NOT_YET_DETERMINED`/non-candidate too (no `source_boundary_evidence` to apply the
   rule to at all, since R05 predates R06's own gate -- unaffected by this correction either
   way).
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

## Build-configuration staleness audit (`audit_build_config_staleness.py`)

Closes the "not audited" risk this document previously disclosed after the node-libcurl fix: if
one frozen `npm_build_configuration.tsv` row was stale, Resource Guard results for the other 96
successfully-replayed packages could not yet be assumed current either. A cheap, configuration-
only audit, no Joern rebuild anywhere:

1. Re-ran the fixed build-configuration extractor (`extract_build_config.py` -- both real
   regression fixes present) against all 97 already-pinned tarballs, by the SAME
   `tarball_url`/`tarball_sha256` identity already recorded in `overnight_sample_100.json` --
   continuing task #34's own narrow download exception, never a new package or URL. Nothing
   touched disk: `classify_from_tarball()` operates on in-memory bytes; each package's own real
   `tarball_sha256` is re-verified before classification, exactly as the original narrow
   exception required.
2. Compared every new result against its frozen TSV row.
3. Counts, over all 97: **UNCHANGED 11, CHANGED 20, CONFLICT 12, UNRESOLVED 54** (full
   per-package detail: `results/build_config_staleness_audit.json`).
4. Reran R06 for every package in CHANGED **or** CONFLICT (32 total) -- not just CHANGED. Reason,
   found while scoping step 4, not assumed from the instruction's own wording: R06's own verdict-
   construction logic (`resource_guard_verdict_r06.py`) only proceeds to a real candidate state
   when `exc_config == "disabled"`; a CONFLICT-bucket package whose frozen TSV row ALSO said
   `disabled` carries the exact same regression risk as a CHANGED one -- a real candidate built
   on a premise (a clean `"disabled"`) the corrected, authoritative extraction shows was never
   actually true (real ambiguity, not a clean value). 25 of the 32 rerun packages had this exact
   shape (old value `disabled`, new value something else); the other 7 were already non-candidate
   abstentions before and after (harmless to rerun, done anyway for a uniform rule). Checked and
   ruled out the mirror-image risk too: zero packages flipped the other direction (old value not
   `disabled`, new value `disabled`) -- no package's build config newly BECOMES `disabled` under
   the fix, so there is no missed-candidate risk to chase here.
5. **Result: zero net change.** All 32 rerun packages had **zero R06 findings in
   `results/replay_records_v4.jsonl` to begin with, at any build-config value** -- R06's own
   contract-matching never found a matching acquisition-call pattern in any of them, so the stale
   config, real as it was, never actually gated anything for these 32. `results/
   replay_records_v5.jsonl` (v4 plus this audit's 32 R06 reruns) is now the current, corrected
   final state; every reportable/candidate/applicable count in this document is unchanged by it.
   Node-libcurl remains the ONE package in this 97-package sample where stale build-config data
   produced an incorrect candidate.
6. Diagnostic-only side finding (never used for the CHANGED/CONFLICT/UNCHANGED decision, since
   `npm_build_configuration.tsv` is itself package-wide): `classify_target_aware()` was also run
   against every real, unambiguous `binding.gyp` found, to check whether a package-wide flat
   verdict was ever papering over real, disagreeing per-target results. 3 packages showed this
   (`@automattic/yara`, `node-libcurl`, `node-snap7` -- real per-target values `enabled` on one
   target, `unresolved` on another). None change this audit's own conclusion: node-libcurl's own
   single R06 finding was already independently confirmed (in the earlier regression fix) to
   resolve against its own correct, specific target.

## Final result, this replay (CORRECTED)

**Zero reportable findings among 97 successfully replayed packages from the frozen 100-package
diagnostic sample; 394 eligible packages were not evaluated by this replay.** (Not "0 reportable
findings, corpus-wide" -- that earlier wording conflated a 97-package diagnostic replay with a
corpus-wide result; see "CORRECTIONS" at the top of this document.)

`rerun_aggregator_applicability.py` (`results/replay_records_v3.jsonl`) plus
`fix_libcurl_build_config_regression.py`'s node-libcurl correction (`v4`) plus
`audit_build_config_staleness.py`'s corpus-wide staleness audit and its 32 targeted R06 reruns
(`results/replay_records_v5.jsonl`, the current, corrected final state -- superseding v2/v3/v4):
**5** real `APPLICABLE` determinations (the 5 staged transitive-tier promotions only --
node-libcurl's own R06 copy no longer reaches `APPLICABLE` at all, its root-cause regression
fixed), **7** real `CONFIRMED_FALSE_POSITIVE` adjudications (the 5 staged sites + node-libcurl's
R05 and R06 copies both, the latter two now a genuine second, independent veto rather than the
only thing masking an incorrect grant), 4 pqclean candidates left genuinely open. Every
fail-closed invariant re-verified directly against the real output, including the new
node-libcurl-applicability-before-adjudication invariant. Full combined gate suite: ALL PASS
(`check_provenance.py` 51/51, `check_oob_reportable_gate.py` 17/17,
`check_vendored_attribution.py` 16/16, `check_reachability_tier.py` 25/25,
`check_staged_enablement.py` 25/25, `check_six_property_aggregator.py` 18/18,
`check_lock_balance.py` 11/11, `check_protected_field.py` 11/11,
`check_adjudication_registry.py` 22/22, `check_applicability_gate.py` 23/23).

## What remains open

- **Task #32 stays partially open**, exactly as instructed: transitive reachability is
  implemented and validated; `CALLBACK_OR_WORKER_HEURISTIC` (124 real candidates) and
  `MODULE_LOAD_EXECUTION_HEURISTIC` (7) remain diagnostic-only, pending their own dedicated
  positive/negative/ambiguity controls -- not built in this round, unchanged by the node-libcurl
  correction.
- **Two structural precision follow-ups, opened (not built) per direct instruction, required
  before expanding to the remaining 394 packages:**
  1. LOCK_BALANCE needs structural recognition of lock-primitive wrapper function definitions
     (`mtx_lock`/`rwlock_rdlock`/`Mutex::lock`-shaped: acquire-and-return by architecture, release
     delegated elsewhere) -- otherwise every future package bundling a similar wrapper repeats
     the same 3-candidate false-positive pattern already seen twice, independently, in this
     round's own 97 packages.
  2. OOB analysis needs type/extent equivalence reasoning (e.g. `uint8_t[6]` vs. a 6-byte
     destination type like `bdaddr_t`) rather than purely syntactic/textual capacity matching --
     otherwise similar cross-variable-`sizeof()` safe copies recur as false positives.
  Their own 5 exact-match adjudications are kept as regressions, unchanged -- see
  `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md`'s own "Recommendation" section for the full account.
- The 4 pqclean candidates stay genuinely open, pending an individual review of the same rigor
  as this one.
- ~~Whether any of the other 96 successfully-replayed packages' own `npm_build_configuration.tsv`
  rows are similarly stale has not been audited~~ **CLOSED -- see "Build-configuration staleness
  audit" above.** 32 were stale; none affected any real R06 finding; `results/
  replay_records_v5.jsonl` is the reconfirmed current state.
- **Remaining blockers before expanding to the 394 unevaluated packages, unchanged by this
  audit** (all four must clear, not just one): (1) LOCK_BALANCE structural primitive-wrapper
  recognition; (2) OOB type/extent equivalence; (3) callback/worker reachability
  (`CALLBACK_OR_WORKER_HEURISTIC`, 124 candidates, diagnostic-only); (4) module-load reachability
  (`MODULE_LOAD_EXECUTION_HEURISTIC`, 7 candidates, diagnostic-only). The current 5 `APPLICABLE`
  staged findings remain useful regression cases (`adjudication_registry.py`'s
  `KNOWN_STAGED_ADJUDICATIONS`), but all 5 are manually confirmed false positives, not evidence
  any of the four blockers above is already resolved.
- The remaining 394 packages stay paused. OOB_COMPARE (task #40) stays disabled.

---
*No new scanning. All changes are recomputation over already-preserved evidence
(`results/replay_records_v2.jsonl` -> `results/replay_records_v3.jsonl` ->
`results/replay_records_v4.jsonl` -> `results/replay_records_v5.jsonl`) plus real,
individually-reviewed adjudications recorded against real published source, plus two rounds of
targeted, preserved-facts-only R06 reruns (node-libcurl's own fix, then the 32-package
build-configuration staleness audit) under corrected build-configuration inputs.*
