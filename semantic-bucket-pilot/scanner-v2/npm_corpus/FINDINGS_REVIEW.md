# NPM corpus scan: results and finding review (items 4/5)

## 1. Real pipeline status across all 494 eligible packages

`npm_pipeline_status.tsv` / `npm_pipeline_full_results.jsonl` (50-package pilot + 444-package
full run, merged):

| Status | Count | % |
|---|---|---|
| ANALYZED | 473 | 95.7% |
| RESOURCE_LIMIT | 18 | 3.6% |
| CPP_CPG_FAILED | 3 | 0.6% |
| **Total** | **494** | 100% |

Real wall-clock for the full run: ~4h45m (08:23-13:01 UTC), all packages processed
sequentially, all intermediate artifacts (tarballs, extracted trees, CPG binaries) deleted
after each package per the frozen pipeline's own design -- disk usage stayed bounded
throughout.

### RESOURCE_LIMIT packages (18) -- real, named, need the high-resource retry queue

`@confluentinc/kafka-javascript@1.10.0`, `@kiran.kk.phonpe/node-native-ocr@0.3.9`,
`smart-whisper@0.8.1`, `@flyskywhy/react-native-gcanvas@6.0.24`, `realm@20.2.0`,
`blake2@5.0.1`, `gdal-async@3.12.3`, `muhammara@6.0.6`, `giac@1.23.69823`,
`@astronautlabs/webrtc@0.6.1`, `mishiro-core@6.3.7`, `libyang@0.13.13`, `gdal@0.11.1`,
`@fugood/whisper.node@1.1.3`, `tree-sitter-fsharp@0.3.11`, `@driftlog/tree-sitter-dart@1.0.4`,
`tree-sitter-4dm@2.11.0`, `detect-character-encoding@0.9.0`.

All real, well-known, genuinely large C/C++ codebases (GDAL, RocksDB-adjacent, tree-sitter
grammar parsers, whisper.cpp bindings, a computer algebra system) -- exactly the kind of
package the pilot's `re2`/`pqclean` cases predicted would need the
`NPM_CORPUS_TIMEOUT_MULTIPLIER=8` retry queue. **Flagged, not yet run** -- per instruction,
this queue is noted here for a deliberate decision, not auto-launched.

### CPP_CPG_FAILED packages (3)

`duckdb@1.4.4`, `rocksdb-lite@1.1.6`, `@farcaster/rocksdb@5.5.0` -- all `c2cpg rc=1` (a real
c2cpg parse/build failure on these specific, large, real codebases; not yet root-caused in
this pass -- these packages remain eligible but unanalyzed, not silently dropped).

## 2. Finding review: zero raw R04 findings -- and why that is NOT a null result

Collecting every `r04_findings` entry across all 473 `ANALYZED` packages: **zero raw
findings, zero after deduplication.** This must NOT be read as "no real, unguarded
`Napi::Buffer::New()` sites exist across 473 real native npm packages" -- investigating WHY
before accepting that reading surfaced a real, corpus-wide **pipeline limitation**, not
evidence about real-world code.

### The real root cause, confirmed by direct re-inspection, not assumed

Aggregate classification across all 473 `ANALYZED` packages:

```
ACQUISITION_NAME_MATCH_CANDIDATE: 18,853
ACQUISITION_SIGNATURE_UNRECOGNIZED: 18,853
ACQUISITION_CALL_FOUND: 0
```

Every single "New"-named call the scanner found (18,853 of them, across 352/473 packages)
was rejected at the qualified-prefix check -- **none** ever resolved to the curated
`Napi.Buffer.New:` signature. Re-ran two real, independent, high-candidate-count packages
outside the pipeline (`@appthreat/sqlite3`, 773 candidates; `node-datachannel`, 400
candidates) to inspect their real, decoded `calls.tsv` directly:

- **Both: 100% of their "New" calls have methodFullName qualifier `<unresolvedNamespace>`**
  (773/773 and 400/400) -- c2cpg never resolved ANY of them to a real, qualified class name,
  not just `Buffer`.
- **Root cause, confirmed:** both packages declare `node-addon-api` as an npm **dependency**
  (`"node-addon-api": "^8.9.2"` / similar) and `#include <napi.h>` in their own source --
  but neither package's own distributed tarball VENDORS `napi.h`/`napi-inl.h` (confirmed:
  `find ... -iname "napi*.h"` finds nothing in either extracted tarball). Real node-addon-api
  usage expects `napi.h` to be resolved from `node_modules/node-addon-api/` after `npm
  install`. **The frozen pipeline (`run_pipeline_one.py`) never runs `npm install` or
  otherwise vendors a package's native dependency headers before invoking `c2cpg`** -- it
  compiles each package's own `.cc`/`.h` files in isolation. Since `napi.h`/`napi-inl.h` are
  entirely header-only (every `Napi::X::New(...)` is an inline/template definition living
  ONLY in those headers), c2cpg has no class/template definition to resolve ANY `Napi::`
  static-factory call against -- it correctly, honestly falls back to
  `<unresolvedNamespace>` for every one of them, exactly the same frontend behavior already
  documented for node-canvas's `Buffer::New` call in `RESOURCE_GUARD_R03.md` -- except this
  reinspection shows it is **systemic across the real corpus**, not a one-off.

### Why R03/R04's own earlier "real" blind tests (jpeg-turbo, Cartesi) DID resolve

Both of those blind-test fixtures were hand-built, minimal, statement-faithful
reconstructions with a locally-defined stub `namespace Napi { class Buffer { ... }; }` in
the SAME translation unit as the function under test (see e.g.
`study/resource_guard_r03/raw_case_jpegturbo_decompress/fixture_source.cpp`) -- not the
real, complete node-addon-api headers, but a real, local, resolvable type definition c2cpg
could see. **The fully-automated corpus pipeline does not do this** -- it runs c2cpg
directly against each package's own unmodified tarball contents, with no dependency headers
present at all. This is the load-bearing difference this run surfaced.

### What this means, stated precisely

- **The zero-finding result across the real corpus is evidence of a pipeline gap (missing
  native-dependency header resolution before c2cpg), not evidence about how common unguarded
  `Napi::Buffer::New()` sites are in real npm packages.** No claim is made either way about
  the latter from this run.
- This gap most likely affects essentially the ENTIRE corpus uniformly, since virtually
  every node-addon-api-based package follows the same "declare as an npm dependency, never
  vendor" convention `@appthreat/sqlite3` and `node-datachannel` both do.
- The fix is a real, buildable pipeline capability -- fetch/vendor each package's declared
  native dependencies' headers (primarily `node-addon-api`, possibly `nan`) before invoking
  `c2cpg`, e.g. via `npm install --ignore-scripts` in the extracted package directory, or by
  directly placing the `node-addon-api` npm package's own headers on the include path. This
  is a genuinely new pipeline capability, not a tweak -- it needs the same
  build-small-validate-then-scale discipline `run_pipeline_one.py` itself followed (a
  compat-adapter-sized fix was already found and fixed once this way during the pilot; this
  is a larger one). **Not attempted in this pass** -- flagging it here for a deliberate
  decision rather than silently re-running the (still-recorded, still-frozen) pipeline
  against all 494 packages again.

## 3. What IS established by this run

- The full, frozen pipeline (download -> dual CPG -> export -> normalize -> cross-language
  link -> R04 scan) runs successfully end-to-end across 473/494 real, independently-verified
  eligible npm packages, with real, bounded resource usage and correct RESOURCE_LIMIT/
  CPP_CPG_FAILED classification for the packages that didn't fit the standard tier.
- Cross-language linking (`link_napi_facts.py` + the disclosed compat adapter) produced real
  registration/link counts for real packages throughout -- a separate, working signal,
  independent of the R04 Buffer-acquisition question.
- R04's own matching/dominance logic was never exercised against a REAL, resolved
  `Napi::Buffer::New` call anywhere in this corpus, for the structural reason above -- so
  this run establishes NOTHING new, positive or negative, about R04's real-world
  generalization beyond what R03/R04's own hand-built blind tests (jpeg-turbo, Cartesi)
  already established. It does establish, newly and concretely, the SCALE of the header-
  resolution gap that blocks it.
