# CROSS_COMPONENT_DEPENDENCIES

Complete result of a full-workspace search (`grep -rl "portable-engine-full-review-package"
--include="*.py" --include="*.sc" --include="*.sh" .`, excluding matches inside Component B
itself) run against the entire top-level source workspace, not just the previously-bundled
files. Five files reference Component B. No more were found by this search; a corresponding
search in the opposite direction (Component B referencing TChecker/gates paths) found none.

| Caller | Imported/referenced file | Reason | Runtime or test-only | Verified working today? |
|---|---|---|---|---|
| `gates/gate_r38.py` | `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/context_state_flow.py` (via `gates/app_mount_flow.py`) | R38's derivation needs `framework_registration.derive()` for router/middleware registration facts | Runtime (the gate cannot produce a result without it) | **YES** -- ran directly, `JS_PROV_R38=10/10, PROMOTION_GATE=PASS`, confirmed again after a genuine `tar` pack/extract round-trip |
| `gates/gate_r39.py` | same, via `gates/app_mount_flow.py` | Same dependency pattern as R38 | Runtime | **NOT TESTED** -- fixture data (`r39-out/`) absent from the source workspace; the import itself was not exercised because the script fails earlier, at `FileNotFoundError` on its own fixture read, before reaching this import path |
| `gates/gate_r40.py` | same, via `gates/app_mount_flow.py` | Same dependency pattern | Runtime | **NOT TESTED** -- same reason as R39 |
| `gates/app_mount_flow.py` | `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/framework_registration.py` (`from framework_registration import derive as derive_regs`) | Shared derivation logic for route/middleware registration identity, reused rather than reimplemented | Runtime | **YES** for the R38 path (confirmed via gate_r38.py actually running); presumed same behavior for R39/R40 given identical code, but not directly exercised for those two |
| `gates/scan_pkg.sh` | `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/module_export_identity.sc` | Runs this Joern script (not a Python import -- a subprocess invocation) as the first step of its fixture-regeneration pipeline, before the 6 gate-specific `.sc` exporters | Runtime, but only when regenerating fixtures from source; not needed to run any already-bundled fixture through its gate | **NOT RE-TESTED** in this pass -- confirmed present and referenced by reading the script; not re-run end-to-end (would require a fresh CPG build), and separately confirmed NOT self-contained in this bundle's directory layout (see `gates/SCAN_PKG_NOT_SELF_CONTAINED.md`) |

## What was checked and found clean

- No file under `tchecker-property-adjudicator/adjudicator/` or
  `tchecker-property-adjudicator/producers/` imports Component B code. JS-SSRF-SOURCE-R01 adds an
  explicit data-contract seam instead: `portable_ssrf_source_bridge.py` consumes Component B's
  `portable-source-facts/0.1` JSON and emits a strict TSV for the optional `browserSourceTsv`
  producer parameter. The components remain code-independent while the provenance handoff is now
  documented and gated.
- No file under `portable-engine-full-review-package/` references anything under
  `tchecker-property-adjudicator/` or `gates/` (checked via the same grep pattern run against
  Component B's own source, searching for `tchecker-property-adjudicator` or `gates/`).
- The dependency is one-directional: `gates/` -> Component B, never the reverse.

## Correction this document represents

An earlier version of this bundle's README stated flatly that no direct runtime/import
integration existed between the two components. That was checked only against
`adjudicate_js.py` and the producer scripts -- it did not check the `gates/` layer, because the
`gates/` layer itself had not yet been found. This document is the result of the corrected,
complete search.
