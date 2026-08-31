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
2. **A finding inside `re2`'s vendored `abseil-cpp` is not automatically a `re2` finding.**
   Every real OOB_WRITE/OOB_READ candidate this pilot found sits under `vendor/abseil-cpp/` —
   bundled third-party source shipped inside the npm tarball, not code the `re2` npm package's
   own maintainers wrote. The prior report named the file paths but did not flag the provenance
   distinction, which matters for attribution, disclosure, and whether the finding is even novel
   (a bug in vendored abseil is abseil's own upstream's to fix, independent of `re2`).

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
| `OOB_WRITE` | Produced real npm candidates (`re2`'s vendored abseil-cpp) — but **needs correction/reproducibility work before being trusted for corpus use**: (a) those candidates are inside vendored third-party source, not package-owned code (task #31); (b) a resolved destination capacity is not itself proof of an overflow — the write length was never shown to exceed it (documented above, not a new blocker, a framing fix); (c) no JS-reachability check exists for any candidate this property produces (task #32). |
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
  silently counted as findings in the npm package under study — task #31.
- If this study's property definition is JS→C/C++ (matching the npm-scoped inventory's own
  framing), a native-code finding needs real evidence linking it to an exposed, JS-callable
  package path — the same discipline `FALLIBLE_BOUNDED_RESOURCE` already applies via
  `link_napi_facts.py` — before it counts as a demonstrated npm-package vulnerability, not merely
  a C/C++-level pattern somewhere in the source tree — task #32.
- Large-package real cost is substantial and now precisely measured, not estimated: ~83s CPG
  generation, ~332s normalization, ~49s for all seven scanner processes combined (re2, 551 real
  files) — real numbers any future corpus-scale cost projection should use, not the small-package
  numbers from phase 1/2 of this pilot.

## Follow-up work opened (read-only judgment, no code changed by this document)

| Task | Blocks |
|---|---|
| #29 — root-cause the `src_capacity_bytes: 5` anomaly | `OOB_READ` (and possibly `OOB_WRITE`/`OOB_COMPARE`'s sibling capacity derivers, sharing the same normalizer machinery) |
| #30 — reconcile the Tremor CVE-2018-5147 reproduction discrepancy | `OOB_WRITE`'s only real historical validation case |
| #31 — vendored-vs-package-owned source provenance classification | `OOB_WRITE`/`OOB_READ` (this pilot's only real npm positives are both vendored), and any future corpus-scale attribution for all six properties |
| #32 — JS/native reachability linkage for the five non-resource-guard properties | `LOCK_BALANCE`, `PROTECTED_FIELD`, `OOB_WRITE`, `OOB_READ`, `OOB_COMPARE` — none currently require it, unlike `FALLIBLE_BOUNDED_RESOURCE` |
| #33 — find or rule out real positive-path evidence for `OOB_COMPARE` | `OOB_COMPARE`'s own promotability basis |

**No 494-package multi-class run is authorized by this document or by task #28's own results.**
That decision is explicitly deferred until the five follow-ups above (or a subset the user
chooses to prioritize) are resolved, per direct instruction.
