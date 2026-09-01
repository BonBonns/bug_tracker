# The 54 unresolved build configurations: relevance split, reason categorization, and the real,
# honest limit of what was mechanically safe to fix

Per direct instruction, following the staleness audit's own disclosed "54 unresolved" count. No
Joern rebuild anywhere -- everything here is either a fresh, narrow, hash-verified re-download
of already-pinned tarballs (continuing task #34's own established exception) or pure
recomputation over already-preserved facts.

## 1. Relevance split (real, not assumed)

| Bucket | Definition | Count |
|---|---|---|
| **R06/Napi acquisition candidates present** | package has ≥1 real R04/R05/R06 finding | **0** |
| **node-addon-api, no acquisition** | `binding_family == "node-addon-api"`, 0 R04/R05/R06 findings | 22 |
| **Nan/raw-NAPI/non-Napi, contract not exercised** | `binding_family` in `{"nan", "none"}` | 32 (15 Nan + 17 "none") |

**The decisive fact, checked directly against `results/replay_records_v5.jsonl`, not assumed:**
all 54 unresolved packages have **zero** R04, R05, and R06 findings -- at any build-config value.
R06's own contract-matching (identifying which real functions LOOK like an acquisition call, a
step that runs entirely independent of `exception_configuration`) never found a matching pattern
in any of them. This means the entire "resolve build config for these 54" question has **zero**
effect on Resource Guard's reportable/candidate output for this 97-package sample -- exactly the
same shape of result the prior staleness audit already found for its own 32 CHANGED/CONFLICT
packages. This is real, disclosed, and re-verified here, not silently assumed to still hold.

Consequence: "packages containing R06/Napi acquisition candidates" -- the bucket step 2's own
"binding.gyp target not mapped to the source file" reason category is about -- is **empty**. That
specific reason category cannot apply to any of the 54; there is no finding's own source file to
map against a gyp target for any of them.

## 2. Unresolved-reason categorization (real, per-package, re-downloaded and inspected directly)

Investigated via `investigate_unresolved_reasons.py` (raw evidence gathering) and confirmed via
the shipped `extract_build_config.classify_unresolved_reason()` (the real, gated function) in
`rerun_extraction_with_unresolved_reasons.py`. Every one of the 54 tarballs was re-fetched by its
already-pinned `tarball_url`, hash-verified against its own recorded `tarball_sha256` before use,
nothing written to disk.

| Reason | Definition (real, mechanically checked) | Count |
|---|---|---|
| `NO_RECOGNIZED_BUILD_FILE` | no binding.gyp/CMakeLists.txt/\*.cmake/meson.build/\*.gn(i) found anywhere in the tarball (a bare package.json is not build-config evidence) | 4 |
| `CMAKE_JS_EXTERNAL_DEFAULT` | a real config file exists, and `cmake-js` is referenced somewhere in the tarball's own real text (its package.json dependency entry) | 8 |
| `NO_TEXTUAL_EVIDENCE` | a real, non-cmake-js config file exists and simply never references any of `DISABLE_PATTERNS`/`ENABLE_PATTERNS` anywhere in its own real text | 42 |

Checked and ruled out, not just unobserved: `bare node_addon_api gyp dependency` (real evidence
distinct from `_except`) was checked for across all 54 -- **zero** matches. `parse_gyp_targets()`
was also checked against every real binding.gyp found -- none carried a real, parseable
`"targets"` array with per-target evidence that a package-wide scan missed (so "binding.gyp
target not mapped to the source file" and "inherited node-addon-api target semantics unresolved"
genuinely do not apply here, beyond the bucket-1 fact above that there is no finding to map at
all). "Conflicting targets" is, by definition, the separate CONFLICT bucket (12 packages,
unaffected by this round -- see the staleness audit's own report), not part of these 54.

## 3. Ranking, and the honest limit of what could be mechanically fixed

Ranked by count: `NO_TEXTUAL_EVIDENCE` (42) > `CMAKE_JS_EXTERNAL_DEFAULT` (8) >
`NO_RECOGNIZED_BUILD_FILE` (4).

**None of the three is safely resolvable to a decisive `enabled`/`disabled`/`conflict` value
without guessing.** This is not a shortfall in this round's own effort -- it is the same,
deliberate, disclosed design boundary `extract_build_config.py`'s own module docstring already
states: default-resolution reasoning (e.g. "the compiler's own real default is exceptions
enabled, absent explicit evidence either way") was, per that docstring, "deliberate, disclosed,
manual investigative work on ONE real site [jpeg-turbo], not a rule this automatic stage applies
to hundreds of packages without individual verification." Promoting any of these 54 to a decisive
value on the strength of "no textual evidence" or "cmake-js is probably going to disable
exceptions by default" would be exactly the same class of regression this whole line of work
(node-libcurl, then the 32-package staleness audit) has spent two rounds correcting: a confident-
looking automated answer standing in for real, individual evidence.

**What WAS mechanically, safely fixed:** `extract_build_config.classify_unresolved_reason()`, a
new, purely diagnostic function. It NEVER changes `exception_configuration` (still always
`"unresolved"` when it is meaningful to call at all) -- by construction, since it never
reimplements or calls the decisive-value logic, only reports a real, textual reason. It exists to
make a future INDIVIDUAL review (the same rigor node-libcurl's own review received) faster to
triage before the 394-package expansion -- distinguishing "nothing to look at" (no build file) from
"look at cmake-js's own build-time behavior for this exact version" from "look at this file's own
text directly, it may simply rely on the compiler default." `check_extract_build_config.py`
(18/18) covers it: positive controls for each real reason, a negative control distinguishing the
two positive cases from each other, conflict-safety controls (never re-diagnoses an
already-decisive or already-conflicting result), a genuinely-unresolved control, an explicit
zero-incorrect-promotion invariant (checked both synthetically and against 5 different real/
synthetic tarball shapes), and a real smoke test against 3 of the 54 real packages.

## 4. Required report block (`rerun_extraction_with_unresolved_reasons.py`)

```
unresolved before: 54
unresolved after:  54
resolved correctly: 20
conflicts preserved: 12
incorrect promotions: 0
```

`resolved correctly: 20` carries forward the prior staleness audit's own 20 CHANGED packages
(the ones whose frozen TSV row differed from the real, live-reproducible answer and were already
corrected in that round) -- this round changed none of them further; `classify_from_tarball()`
itself is byte-for-byte unchanged this round, asserted directly against the prior round's own
stored per-package result for all 97, not assumed. `conflicts preserved: 12` is the same 12
CONFLICT packages from the prior round, still real, unresolved ambiguity (both real enable and
disable evidence genuinely present in their own real text) -- correctly never forced to a
decisive value either. `incorrect promotions: 0` is checked directly, not merely absent from the
diff: zero packages moved from a real, resolvable state to `"unresolved"`, and zero moved from
`"unresolved"` to a decisive value.

## 5. Step 6 -- rerun R06 only for packages whose configuration changed

**Zero packages.** `config_changed_packages` (computed by comparing this round's fresh
`classify_from_tarball()` output against the prior round's own stored result for all 97 real
packages) is the empty list -- confirmed programmatically, not assumed from "no promotions
happened." No R06 rerun was needed or performed this round; `results/replay_records_v5.jsonl`
remains the current, correct final state.

## What this round establishes, and what it leaves open

- The 54 unresolved packages are now correctly, evidence-backed **triaged**, not merely counted.
  A future individual review (the same rigor as node-libcurl's own) has a real starting point per
  package instead of an opaque "unresolved."
- Because zero of the 54 have any Resource Guard finding today, none of this round's own findings
  change the current reportability funnel (still 0 reportable, 5 `APPLICABLE`, per
  `APPLICABILITY_GATE_RESULTS.md`).
- This DOES matter for the eventual 394-package expansion: `CMAKE_JS_EXTERNAL_DEFAULT` and
  `NO_TEXTUAL_EVIDENCE` will very likely recur at scale, and a future package in one of those
  buckets COULD carry a real R06 acquisition candidate (unlike any of these particular 54) --
  the diagnostic reason this round adds is exactly what makes that future review tractable
  without repeating this round's own from-scratch investigation.

---
*No new scanning, no Joern rebuild. All changes are either a narrow, hash-verified re-download of
already-pinned tarballs (continuing task #34's own established exception) or pure recomputation
(`classify_unresolved_reason()` is diagnostic-only, byte-for-byte independent of
`classify_from_tarball()`'s own decisive-value logic).*
