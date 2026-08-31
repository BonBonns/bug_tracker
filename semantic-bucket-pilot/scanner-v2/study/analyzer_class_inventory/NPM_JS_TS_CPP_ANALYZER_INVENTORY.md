# NPM JS/TS↔C/C++ analyzer inventory — project-scoped totals

This is the project-relevant document. `README.md` in this same directory is the
repository-wide inventory (26 properties across npm-native-addon, general C/C++, JS/TS, and
PHP/WordPress work); this document filters that same normalized data
(`data/properties.csv` etc., `WHERE npm_applicable == TRUE`) down to the **20 properties that
actually apply to this project** — JS/TS-to-C/C++ npm packages, the ecosystem the stopped
494-package pipeline targets. The 6 PHP/WordPress properties are a different project entirely
(a WordPress-plugin taint engine, different language, different Joern frontend, never invoked
by anything in this project) and are excluded here **by construction** — filtered by the same
`npm_applicable` column already present in the repository-wide table, not by a second,
independent judgment call that could disagree with it. They remain visible only as the
repository-wide appendix in `README.md`.

Reproduce every number below with `python3 compute_npm_totals.py`.

## The central project conclusion

**The stopped npm pipeline evaluated 1 of 20 npm-applicable implemented properties — not 1 of
26 repository-wide properties.** 26 was never the right denominator for "was the npm dataset
comprehensively scanned" — it included 6 properties (PHP/WordPress) that could not have run
against this corpus under any circumstance, regardless of wiring effort. 20 is the honest
denominator: every one of these properties could, in principle, be pointed at the same 494
eligible packages.

## Scope-corrected totals

| Metric | Value |
|---|---|
| Total repository-wide implemented properties | 26 |
| **npm-applicable properties (this project's scope)** | **20** |
| Excluded as out-of-project (PHP/WordPress, separate appendix) | 6 |
| Promotable (SOUND), npm scope | **18** |
| Unverified, npm scope | 1 — `PATH_TRAVERSAL` |
| Unsound, npm scope | 1 — `COMMAND_INJECTION` |
| **Executed by the stopped 494-package pipeline** | **1 of 20** — `FALLIBLE_BOUNDED_RESOURCE` |
| Not executed | 19 |

This matches the breakdown you derived from the disclosed status list exactly: 18 sound / 1
unverified (Path Traversal) / 1 unsound (Command Injection).

## Historical evidence, re-scoped: npm-corpus evidence vs. other-ecosystem validation

The repository-wide document's "10 properties have historical corpus evidence" conflated real
validation against genuinely different ecosystems with evaluation on the target corpus. Re-run
with an explicit `ecosystem_scope` column on every `historical_runs.csv` row, restricted to the
20 npm-applicable properties:

| `ecosystem_scope` | Count | Properties |
|---|---:|---|
| `NPM_NATIVE_ADDON_CORPUS` — same target class as the 494-package corpus | **1** | `FALLIBLE_BOUNDED_RESOURCE` (the pre-header-fix full 494-package R01–R04 run, plus the Nan capability's own real-package runs on node-snap7/libpq) |
| `NPM_PACKAGE_GENERAL` — npm-published, not confirmed native-addon-specific | **1** | `MALICIOUS_NPM_INSTALL_EXFIL` (13/13 real cases; the property is npm-supply-chain-specific by design, but available docs don't confirm the targets were native-addon packages or the 494-corpus itself) |
| `OTHER_ECOSYSTEM` — real validation, but off the npm native-addon corpus (**not counted as npm-scoped evidence**) | **8** | `LOCK_BALANCE`/`PROTECTED_FIELD` (wolfSSL), `OOB_WRITE` (Tor corpus, Mozilla CVEs), `GUARD_FALLTHROUGH` (WordPress core `admin-ajax.js`), `UNGUARDED_SERIALIZE_DOS` (mozilla/fxa, novuhq/novu — neither is a native-addon package), `REDOS` (1,477-file scan + RocketChat), `LLM_INSECURE_OUTPUT_HANDLING`/`LLM_PROMPT_INJECTION` (RocketChat) |
| No historical run evidence of any kind | 10 | `OOB_READ`, `OOB_COMPARE`, `DENYLIST_PATTERN_BYPASS`, `GLOBAL_SINGLETON_MUTATION`, `VALIDATION_BYPASS`, `SSRF`, `PATH_TRAVERSAL`, `FAIL_OPEN_SECURITY_CONTROL`, `NOSQLI` (Stage3 attempted, abandoned), `COMMAND_INJECTION` |

wolfSSL, Tor, Mozilla (both the C/C++ NSS/mozjpeg work and the JS `mozilla/fxa` project),
WordPress, and RocketChat evidence is real and useful for establishing a property's own
soundness — but per your framing, none of it is equivalent to evaluation on the 494
native-addon packages, and it is now marked as such rather than folded into an undifferentiated
"has historical evidence" count.

## Readiness breakdown — the missing metric, npm scope only

Requested categories, computed from `data/npm_readiness.csv` (one row per npm-applicable
property, cross-checked 1:1 against `properties.csv`'s own npm-applicable set by
`compute_npm_totals.py` — a missing or extra row fails loudly rather than silently skewing a
count):

| Status | Count | Properties |
|---|---:|---|
| **`ALREADY_EXECUTED`** | 1 | `FALLIBLE_BOUNDED_RESOURCE` |
| **`READY_TO_WIRE_WITH_CURRENT_FACTS`** | 5 | `LOCK_BALANCE`, `PROTECTED_FIELD`, `OOB_WRITE`, `OOB_READ`, `OOB_COMPARE` — all consume `export_c_cpp_facts_v03.sc`, the same raw C/C++ fact table `run_pipeline_one.py` already generates for every package. This matches your own "four useful C/C++ properties" observation exactly: resource-guard (already executed) + lock-balance + protected-field + OOB(-write/read/compare, one property family) |
| **`NEEDS_SPECIALIZED_EXPORT`** | 12 | `DENYLIST_PATTERN_BYPASS`, `GLOBAL_SINGLETON_MUTATION`, `GUARD_FALLTHROUGH`, `MALICIOUS_NPM_INSTALL_EXFIL`, `UNGUARDED_SERIALIZE_DOS`, `VALIDATION_BYPASS`, `SSRF`, `REDOS`, `NOSQLI`, `FAIL_OPEN_SECURITY_CONTROL`, `LLM_INSECURE_OUTPUT_HANDLING`, `LLM_PROMPT_INJECTION` — sound (or sound-with-a-disclosed-caveat, `NOSQLI`'s Stage3 gap), but each needs its own specialized Joern export the npm pipeline's generic `export_neutral.sc` stage doesn't produce |
| **`NEEDS_SOUNDNESS_WORK`** | 1 | `COMMAND_INJECTION` — Stage 2B is self-described as an experiment, never wired to a promotion path; this is a soundness gap, not an export gap |
| **`UNVERIFIED`** | 1 | `PATH_TRAVERSAL` — wired to the shared taint engine but no dedicated gate/freeze doc confirms its own soundness |

Sums to 20, checked by assertion in `compute_npm_totals.py`.

## What this does not change

`README.md`'s repository-wide totals (26 properties, 11 infrastructure components, the
`single_object_pass.py`/`OOB_WRITE` and Gate-39 corrections) are unchanged and still the
authoritative repository-wide record — this document is a re-scoped *view* built on the same
underlying `data/*.csv`, not a re-derivation from scratch, and any future edit to
`properties.csv`/`implementations.csv` automatically flows into both documents' scripts without
needing to be kept in sync by hand.

No scanner, contract, exporter, or pipeline file was modified or run to produce this document —
only this study's own CSV tables and `compute_npm_totals.py`, consistent with the standing
read-only instruction. `npm_readiness.csv`'s status assignments and `historical_runs.csv`'s
`ecosystem_scope` column are judgment calls made from the same already-cited freeze/review docs
this whole inventory has relied on throughout — not independently re-verified against fresh
scanner output this pass.
