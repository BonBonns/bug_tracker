# Nan capability freeze

The two contracts below are frozen as of this document. No further changes are planned to
`resource_contracts_nan.py` or `resource_guard_verdict_nan.py` unless a new real defect is
found the same way the three documented in `NAN_CAPABILITY_DESIGN.md` Sections 6/6b were —
two by running against real, structurally diverse corpus code, one by a direct challenge to
this capability's own real result, verified against real facts rather than conceded or
defended on principle alone.

## Frozen files

- `resource_contracts_nan.py` — the two contracts (`NAN_NEWBUFFER_UNBOUNDED_ALLOCATION`,
  `NAN_COPYBUFFER_SOURCE_CAPACITY`), per-arity size/source argument indices, the real Nan
  CallbackInfo type marker.
- `resource_guard_verdict_nan.py` — the verdict engine: registration extraction, the
  CallbackInfo-index backward trace, the upper-bound-check detector, the CopyBuffer
  source-capacity resolver, and the two contracts' evidence-chain orchestration.
- `tests/test_resource_guard_verdict_nan.py` — 25/25 real assertions against
  `study/nan_capability/controls/comprehensive_fixture/`'s real, c2cpg/jssrc2cpg-produced raw
  facts (9 purpose-built cases, every contract-boundary decision covered).

Standalone from the R04-R06/FIX01I lineage throughout — verified by inspection: neither file
imports anything from `resource_guard_verdict_r04/r05/r06.py`, `resource_contracts_r04/r05.py`,
or `promote_via_js_linkage.py`. No R04-R06/FIX01I file, contract, exporter, or normalizer was
modified anywhere in this capability's development.

## What is frozen (the real, verified evidence chain)

For `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION`, promotion to a candidate finding requires ALL of:

1. A real `Nan::NewBuffer(...)` call matching one of the three real overloads (arity 1, 2, or
   4 — Section 2 of the design doc), with a non-literal size argument.
2. A real backward trace from that size argument to a real `info[N]` access on a parameter
   whose own type is `Nan.NAN_METHOD_ARGS_TYPE`/`Nan::NAN_METHOD_ARGS_TYPE` — via either the
   direct-chain shape (confirmed real on every corpus positive found) or the out-parameter
   shape (structural parity only, not yet observed on real Nan code).
3. A real registration of the enclosing method via `Nan::SetPrototypeMethod`/`Nan::SetMethod`,
   resolved to exactly one real, class-scoped candidate function.
4. Real JS reachability, established via EITHER of two explicit, disclosed tiers (recorded as
   `js_reachability_tier` in the finding's own evidence, never conflated): `"confirmed_call"`
   — a real JS call by the registered name, in the package's own real JS/TS source, supplying
   a real argument at the required index (`callback_info_index + 1`); or
   `"exported_registration"` — no specific call observed, but the package's own JS entry point
   unconditionally re-exports its whole native binding (`module.exports = require(<bindings|
   node-gyp-build>)(...)`, verified via `is_native_module_directly_exported` — see
   `NAN_CAPABILITY_DESIGN.md` Section 6b for the real node-snap7 case that required this).
5. No structural upper-bound check found on the traced value (or any identifier in its own
   def-chain) before the acquisition call.

For `NAN_COPYBUFFER_SOURCE_CAPACITY`, conditions 1-4 apply to `Nan::CopyBuffer(...)`'s length
argument (the only real overload, arity 2), PLUS: a real, local allocation site for the source
pointer was found in the same method, whose own size is structurally different (not the same
identifier/literal) from the traced length — never promoted merely because the source's origin
could not be resolved (that is `NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED`, a distinct,
disclosed abstention).

## Real validation this freeze rests on

- **25/25 fixture assertions passing** against real raw facts from an actual c2cpg/jssrc2cpg
  run (`study/nan_capability/controls/comprehensive_fixture/`, reproducible via that
  directory's own `build_fixture.sh`) — 9 cases covering every contract-boundary decision,
  including two adversarial cases (an explicit bound check; a capacity that matches by
  construction) that must NOT promote.
- **6 independently-verified real negative-control packages, 0 false positives**:
  `murmurhash-native`, `msgpack`, `@confluentinc/kafka-javascript`, `scrypt`, `libpq`,
  `phplike` — the same six the prevalence study manually confirmed as real negatives, now
  independently reconfirmed by the automated tool itself, through the real pipeline
  (c2cpg + jssrc2cpg + both export stages), not merely re-asserted.
- **3 real, structurally distinct positives on `node-snap7`**: `ReadArea` — real registration,
  real `info[3]`/`info[4]` chain (`amount * byteCount`), real confirmed JS call
  (`this.readAreaLike(...)` in the package's own bundled `lib/node-snap7.js`, `"confirmed_call"`
  tier), no detected bound check; `Upload`/`FullUpload` — structurally identical in C++, real
  registration + real `info[N]` chain, no call observed in the package's own bundled wrapper,
  but the package's own JS entry point unconditionally re-exports the whole native binding
  (`"exported_registration"` tier — see `NAN_CAPABILITY_DESIGN.md` Section 6b). All three
  reported as STATIC CANDIDATES (`NAN_CAPABILITY_DESIGN.md` Section 4's disclaimer verbatim in
  each finding's own `evidence_note`), never a vulnerability or CWE claim.
- **Registration alone is still never sufficient on its own** — a method that is BOTH
  unregistered (`node-snap7`'s own synthetic-shaped internal helpers) and a package that
  neither confirms a call NOR unconditionally re-exports its native binding both still
  correctly abstain, matching the project's established discipline (Cartesi's own WASM case,
  `node-libcurl`'s own native-callback case) — the `exported_registration` tier is a second,
  real, disclosed, WEAKER-but-still-structural path to the same conclusion, not a relaxation
  of the requirement that JS reachability be established by real evidence.
- **Three real defects found and fixed, none by inspection alone** — `NAN_CAPABILITY_DESIGN.md`
  Sections 6/6b. All three corrections moved results toward MORE ACCURATE promotion, not
  toward promoting more freely: fixing a false negative on node-snap7's own real registrations
  (Bug 1); fixing a false positive on libpq's own real `GetCopyData` (Bug 2); fixing a second,
  distinct false negative on `Upload`/`FullUpload` by recognizing a real, disclosed, narrower
  reachability tier (Section 6b) rather than either loosening the requirement generally or
  defending the original, too-strict design on principle.
- **`node-snap7-micro-client`** (the same real S7 codebase, separate npm identity) reproduces
  the identical 3 positives at the identical tiers — a real, if modest, stability check across
  two independently-tarballed copies of nearly the same source.

## Explicitly frozen OUT of scope (see design doc Section 8 for the complete list)

No applicability/failure-mode gate; no downstream-write tracing to confirm the integer-overflow
consequence named in the disclaimer is actually reachable; the `SIZE_LITERAL_NOT_APPLICABLE`
vs. `SOURCE_BOUNDARY_UNRESOLVED` categorization is coarser than ideal for a literal reached via
an intermediate identifier. None of these affect this freeze's own correctness claims — they
are disclosed scope limits, not open defects.

## Blind test: explicitly NOT selected or read in this pass

Per instruction, this freeze is the checkpoint before any blind-test package is chosen. No
package beyond the development case (`node-snap7`/`node-snap7-micro-client`) and the six
already-known negative controls has been read for this capability's own purposes. Selecting
and reading a genuinely independent blind-test package is the next phase's work, not this
one's.

## Corpus scope note

This capability was developed and validated against 8 real packages read individually
(`node-snap7`, `node-snap7-micro-client`, and the 6 negative controls) — it has NOT been run
against the broader 494-package corpus the R04/R05 lineage was run against (that corpus scan
was stopped at 452/494 by explicit instruction, its own class already having substantial
evidence in hand — see `study/ANALYZER_CLASS_COVERAGE_MATRIX.md`). Running this capability
against that broader corpus, if desired, is separate future work, not implied by this freeze.
