# Task #28: corrected pilot conclusion, and the follow-up work it opens

`BEHAVIORAL_VERIFICATION_RESULTS.md` (phase 3) reported real evidence for every step it was
asked to run, but its own framing was read as more conclusive than the evidence supports on two
specific points, corrected here directly rather than edited away silently:

1. **A destination capacity of 100 does not, by itself, establish an OOB write.** The prior
   report's own Section 3.3 said `dest_capacity_bytes: 100` was "verified... against the real
   source" — true only as a claim about the *capacity value itself* (the deriver correctly read
   `char buf[100]`). It never claimed, and should have said so explicitly, that the site's own
   *write length* (the `snprintf` call's own size argument) was shown to exceed 100 — it was not
   checked. `oob_write_verdict.py`'s own CANDIDATE verdict already means exactly this narrower
   thing by design ("no PROVEN bound", not "proven overflow") but the report's prose did not say
   so plainly enough on first read.
2. **A finding inside `re2`'s vendored `abseil-cpp` is not automatically a `re2` finding —
   but it must be CLASSIFIED, not discarded.** Every real OOB_WRITE/OOB_READ candidate this
   pilot found sits under `vendor/abseil-cpp/` — bundled third-party source shipped inside the
   npm tarball, not code the `re2` npm package's own maintainers wrote. The prior report named
   the file paths but did not flag the provenance distinction. **Correction to the correction**:
   this does not mean vendored findings should be thrown away. A vendored dependency that is
   actually compiled into the addon and reachable through it (task #32's own reachability tiers)
   can still contain a real, exploitable bug reachable via the npm package — the fix is
   attribution (report it as "<upstream library> as bundled by <npm package>", not an unqualified
   `re2` finding) and deduplication (the same vendored library bundled near-identically by many
   packages should not count as N independent findings), never silent exclusion. See task #31,
   revised accordingly.

Both corrections, plus two structural gaps the pilot's own real evidence surfaced but did not
resolve, are the basis for the corrected property status below and the five follow-up tasks
opened as a direct result (project task tracker #29-33). **The 494-package multi-class run
remains explicitly not authorized — this document does not change that.**

## Corrected per-property status

| Property | Status |
|---|---|
| `FALLIBLE_BOUNDED_RESOURCE` | Existing corpus baseline (already executed by the stopped 494-package run), but with known precision problems already disclosed elsewhere in this repository (R05's near-miss audit, the node-libcurl false positive, the `static_cast<Napi::Value>` object-identity gap) — not re-litigated here. |
| `LOCK_BALANCE` | **Closest to integration-ready.** Real schema/execution compatibility, a real historical positive+confirmed-negative pair reproduced fresh through the real pipeline, a real explicit-abstention path demonstrated (synthetic, disclosed). Its one open gap: real npm positive-path evidence is still absent (the one real npm lock-call candidate this pilot found, `@2060.io/ffi-napi`'s `closures.c`, never made it into the CPG at all, for an unexplained reason). |
| `PROTECTED_FIELD` | Integration works (schema-compatible, real historical positive and a real, precisely-documented abstention reproduced). **Needs target-domain evidence** — zero real npm evidence either way; its own inference rule (a field protected in one place, unprotected in another, same translation unit) makes real npm exemplars genuinely hard to find by cheap search, not yet attempted at the scale this would need. |
| `OOB_WRITE` | Produced real npm candidates (`re2`'s vendored abseil-cpp) — but **needs correction/reproducibility work before being trusted for corpus use**: (a) those candidates are inside vendored third-party source, which needs classification and dedup, not exclusion (task #31); (b) a resolved destination capacity is not itself proof of an overflow — the write length was never shown to exceed it (documented above, not a new blocker, a framing fix); (c) no tiered JS-reachability classification exists for any candidate this property produces (task #32). |
| `OOB_READ` | **Blocked.** The repeated, implausible `src_capacity_bytes: 5` (including on a function-pointer-typed source) strongly suggests a real, unresolved capacity-derivation defect (task #29) — its positive-path output cannot be trusted at corpus scale until this is root-caused. |
| `OOB_COMPARE` | **Blocked.** Zero positive-path evidence exists anywhere — not in this pilot's real npm/historical testing, not in this repository's own prior Tor-corpus validation (0-for-12 real sites). Its promotability currently rests entirely on gate-fixture soundness, with no real-world positive validation to date (task #33). |

**The pilot is complete as an experiment. Its answer is not "launch the corpus run" — it is "one
property (`LOCK_BALANCE`) is close to integration-ready, one (`PROTECTED_FIELD`) needs
target-domain evidence, and the three OOB properties need a dedicated correction/reproducibility
phase before corpus use, especially `OOB_READ` and `OOB_COMPARE`."**

## Additional blockers, stated plainly

- The committed Tremor CVE-2018-5147 fixture's previously-documented positive result could not
  be reproduced through this pilot's own real pipeline invocation (0 candidates on both vuln and
  patched) — task #30.
- A resolved destination capacity alone does not establish an OOB write; the actual write extent
  must be shown to exceed it — a framing correction to `BEHAVIORAL_VERIFICATION_RESULTS.md`
  Section 3.3, not a new defect, but real enough to restate here plainly.
- Findings inside vendored third-party source (e.g. `re2`'s bundled `abseil-cpp`) must not be
  silently counted as unqualified findings against the npm package under study — but they must
  not be silently discarded either. A reachable vendored bug is a real bug; it needs attribution
  (upstream library, not the bundling package) and deduplication (not counted once per bundling
  package) — task #31, revised.
- If this study's property definition is JS→C/C++ (matching the npm-scoped inventory's own
  framing), a native-code finding needs real evidence linking it to an exposed, JS-callable
  package path — the same discipline `FALLIBLE_BOUNDED_RESOURCE` already applies via
  `link_napi_facts.py` — before it counts as a demonstrated npm-package vulnerability, not merely
  a C/C++-level pattern somewhere in the source tree. **Revised per direct instruction: this must
  be a 6-tier reachability classification (direct linked call; exported registration without an
  internal wrapper call; transitive native helper; registered callback/worker; module-load-time
  execution; unresolved), not a single direct-call-only gate — a single-tier requirement would
  recreate the exact false-negative problem already found and fixed for Nan's exported-but-
  unwrapped methods, and would miss transitively-called native helpers entirely** — task #32.
- Large-package real cost is substantial and now precisely measured, not estimated: ~83s CPG
  generation, ~332s normalization, ~49s for all seven scanner processes combined (re2, 551 real
  files) — real numbers any future corpus-scale cost projection should use, not the small-package
  numbers from phase 1/2 of this pilot.

## Follow-up work opened, in recommended priority order (read-only judgment, no code changed
## by this document)

| Order | Task | Scope |
|---:|---|---|
| 1 | #29 | Root-cause the `src_capacity_bytes: 5` anomaly |
| 2 | #30 | Reconcile the Tremor CVE-2018-5147 reproduction discrepancy |
| 3 | #32 | **Tiered** (6-level) JS/native reachability classification, not a single direct-call gate — per the Nan-capability false-negative lesson |
| 3.5 | #35 (new) | Every finding must preserve its real source path + a content hash at scan time |
| 4 | #31 | Vendored-source **provenance classification and deduplication** (not exclusion) |
| 5 | #33 | Find real positive-path evidence for `OOB_COMPARE`, **or formally retire it from promotion** if a genuine, bounded search finds none |

## Property-specific blockers (revised again: #35 is universal, not OOB-only)

Per direct instruction, the blockers are property-specific rather than one all-or-nothing gate —
a staged run can enable whichever properties have their own preconditions met, instead of every
property waiting for the weakest one. **Correction to the prior revision**: #35 was scoped there
to `OOB_WRITE`/`OOB_READ` only, on the reasoning that those were the only properties with real
vendored findings observed so far. That was wrong — the underlying fact this pilot itself
established is that **none of the six properties currently preserves source path or content
hash**, so #35 must gate every property that emits findings, not just the two that happened to
produce a vendored candidate first. Two explicit conditions govern when a task is genuinely
non-gating for the overall run:

- **#31 stays non-gating only if #35 (source path + content hash, at scan time, for every
  property) is done first.** Without that data captured before the source tree is deleted,
  vendored provenance and cross-package deduplication cannot be reconstructed after any run
  completes — for any property, not only the ones already observed hitting vendored code.
- **#33 alone does not clear `OOB_COMPARE` for enablement.** Finding a real positive example
  would only prove `OOB_COMPARE`'s own property logic is sound — it would still need the same
  cross-language reachability (#32) and source provenance preservation (#35) every other native
  finding needs before being reported as a demonstrated npm-package vulnerability. #33 remains
  the reason `OOB_COMPARE` must stay fully DISABLED (not merely unattributed) until real
  positive-path evidence is found or the property is retired — its own zero-candidate output
  must never be reported as a meaningful negative while #33 is open — but #32 and #35 apply to it
  exactly as they apply to the other four properties.

| Property | Task tracker gate | Blocked by |
|---|---|---|
| `LOCK_BALANCE` | #36 — Enable in staged run | #32, #35 |
| `PROTECTED_FIELD` | #37 — Enable in staged run | #32, #35 |
| `OOB_WRITE` | #38 — Enable in staged run | #30, #32, #35 |
| `OOB_READ` | #39 — Enable in staged run | #29, #30, #32, #35 |
| `OOB_COMPARE` | #40 — Enable in staged run | #33, #32, #35 |

**#34 (the original blanket gate, kept for the case a FULL, all-five-properties-simultaneous run
is specifically wanted) now requires #29 + #30 + #32 + #33 + #35 all resolved** — #33 and #35
were added on this same correction, since the full run by definition includes `OOB_COMPARE`
(gated by #33) and every property (gated by #35). **Equivalently**, #34 can be treated as an
aggregator that is ready exactly when #36, #37, #38, #39, and #40 are all individually
satisfied — the two framings describe the same underlying condition. The staged path (#36-#40)
remains the recommended way to proceed: e.g. `LOCK_BALANCE` alone could be enabled via #36 once
#32 and #35 both land, without waiting on #29/#30/#33 at all.

### What #35 must preserve, at scan time, per direct instruction

Provenance classification itself (#31) may happen later, but the evidence it needs cannot be
recreated once a run's source tree is deleted — so #35's own work is to capture, for every
finding, before that deletion:

1. package name and pinned version;
2. a source-tree hash (one hash over the whole extracted source tree's state at scan time);
3. the exact relative source path of the finding's own site;
4. a content hash of that specific source file;
5. the finding's own line/node identity (already present in most current output — must not
   regress);
6. a best-effort package-authored-vs-vendored flag, only where already cheaply determinable at
   scan time (e.g. a `vendor/`/`deps/`/`third_party/` path heuristic) — not a substitute for
   #31's own later, authoritative classification, only a preservation of whatever signal would
   otherwise be lost.
