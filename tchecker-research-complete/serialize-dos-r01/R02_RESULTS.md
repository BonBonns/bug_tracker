# SERIALIZE-DOS-R02 -- manual review, architectural correction, and validation

Continues directly from R01 (`RECONCILIATION.md`, `VALIDATION_RESULTS.md`). This
document covers: the manual review of R01's frozen `motifer@26.1.1` blind finding, the
architectural correction it required, R02 itself, and R02's own blind-package run.

## 1. Manual review of the frozen `motifer@26.1.1` result

Full detail, with every claim backed by an independently fetched, hash-verified
artifact (Express's own pinned-version source, body-parser's own source, motifer's own
README, and a standalone diagnostic Joern script that never edits any frozen
analyzer): `study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md`. Summary of the six
required checks:

1. **Exact function**: the anonymous middleware at `index.js:167-193`, registered via
   `express.use(...)` inside the exported `ExpressLoggerFactory`.
2. **Real invocation path**: yes -- the package's own documented, primary usage
   pattern (`README.md`), not a rare code path.
3. **Exact node-identity flow**: `req.body` is read twice at line 188 (ternary
   condition + `JSON.stringify` argument, two distinct AST nodes). The frozen taint
   engine's own automated run reports `NO_FLOW` because `setup_candidate.sc` picks the
   FIRST occurrence (the condition, which has zero flow to the sink) -- a real,
   disclosed limitation of that producer, confirmed via a standalone diagnostic script
   using the same underlying `reachableByFlows` engine on the CORRECT node (the
   argument's own occurrence, id-identical to the sink argument -- the most direct
   flow shape possible).
4. **Upstream body-size limit**: not established by motifer's own code. In the
   package's own documented default configuration (`bodyParser.json()`, no `limit`
   override), a real but **consumer-chosen** 100KB cap applies (confirmed from
   `body-parser@1.20.4`'s own source) -- not an analyzer-verifiable guard.
5. **Exception boundary**: no local guard, but Express 4.22.1's own
   `Layer.prototype.handle_request` (confirmed from Express's own pinned-version
   source) wraps every standard synchronous middleware call in `try { fn(...) } catch
   (err) { next(err) }` -- a real, framework-level catch boundary, unmodeled by either
   the direct crash-safety analyzer or R01's reuse of it.
6. **Do both axes genuinely apply? No, only one.**
   - **Crash-safety: adjudicated REJECTED**, without any analyzer code change --
     Express's own dispatch layer catches the synchronous throw; it does not crash the
     process.
   - **Size/structure: confirmed on manual review** -- the true dataflow is real and
     maximally direct, though the automated taint-engine pipeline currently
     misreports it (item 3), and its real-world severity is meaningfully (but not
     guaranteed-package-independently) bounded by a consumer-chosen 100KB default.

**R01's original two-candidate result is not treated as confirmed.** Per instruction,
both axes emitting a candidate is not itself confirmation.

## 2. Why this triggers the architectural correction, not just an adjudication

The crash-safety axis was settled by manual review alone -- no code changed. The
size/structure axis is different: the manual review process exposed that R01 never
actually consulted the real taint engine (its `size_structure_dos_classification` was
an independent, narrower approximation that happened to agree here), AND that the
taint engine's own automated pipeline (`setup_candidate.sc`) has a real, generalizable
limitation that would make an automated re-run of THIS exact case currently wrong. That
combination -- the existing size-axis architecture in R01 was not defensible, and the
canonical engine's automated output cannot currently be trusted blindly on this shape
-- is the "analyzer requires modification" branch. Per instruction: **motifer is
treated as development evidence, not frozen as a clean regression.** R02 is the
correction; a new package was mechanically selected for R02's own blind validation
(Sec.4).

## 3. R02: coordinator, not a replacement

`serialize_dos_r02.py` (full docstring has the complete rationale):

- `crash_dos_classification`: **unchanged** -- still reuses
  `gates/serialize_dos_verdict.py`'s guard logic verbatim. The direct analyzer remains
  canonical for crash-safety; this review did not find a reason to touch it (motifer's
  crash-safety miss was a modeling GAP -- framework dispatch boundaries -- not
  something in scope to fix here, and is disclosed, not patched, per instruction not to
  modify the analyzer as part of this review).
- `size_structure_dos_classification`: **now sourced from the real taint engine's own
  `evidence_final.json` disposition**, produced by the actual, unmodified
  `setup_candidate.sc` -> `export_property_propagation.sc` -> `export_trace_identity.sc`
  -> `adjudicate_js.py` pipeline, run externally per candidate site (same operational
  convention as every other property in this session -- Joern invocation lives outside
  the `.py` reducer). R02 does not compute this itself; it only maps the taint engine's
  own disposition string into its own vocabulary. R01's old `transform_presence.tsv`
  approximation survives only as `size_structure_structural_prefilter`, explicitly
  documented as non-authoritative.

Real per-fixture validation: each of R01's 7 fixtures was individually recompiled
(`setup_candidate.sc` needs one sink per CPG -- a real, disclosed scope note now
documented in R02's own module docstring) and run through the full, real taint-engine
pipeline. Gate: `check_serialize_dos_r02.py`, **`SERIALIZE_DOS_R02=11/11`**. Notably,
`sd-transform-present` now reports `ABSTAIN_TAINT_ENGINE_OPEN` sourced from the taint
engine's own real `CANDIDATE_OPEN` disposition -- not R01's own guess (which happened
to also abstain, but for a different, self-computed reason) -- directly exercising the
architectural correction.

Frozen implementation hashes:
```
f76f3a3d4637aba7816923a24dccfc34e311e6aa05123a6c1d251947bb6bbb91  serialize_dos_r02.py
3397b1e84b3ad73a0c7198f6b2d655de3845d065ad8e7649c3a8b91975448504  check_serialize_dos_r02.py
```

## 4. R02 blind package (mechanical selection)

Procedure recorded in full before any inspection:
`study/BLIND_PACKAGE_SELECTION_R02.txt`. Index formula unchanged from R01
(`int(sha256(frozen_module)[:8], 16) % 20` against a live npm registry search), a
different keyword than R01's draw (`keywords:request-logging` vs.
`keywords:express-middleware`) to avoid any appearance of steering toward a repeat.

- **Index 17 -> `@sonatel-os/juf-xpress-logger@1.0.0`: a confirmed TOOLING failure**,
  not a content-based skip. It ships only a bundled `dist/index.cjs.js` (no source);
  `astgen` itself parsed it fine (537KB AST JSON, no errors), but `jssrc2cpg` silently
  produced an EMPTY CPG for it (0 files, 0 methods, 0 calls -- confirmed by a direct
  count query, `study/blind_r02_juf_xpress_logger_TOOLING_FAILURE/`). A fallback rule
  was declared **at the moment of, and disclosed in,** this failure (not
  pre-registered before starting, since no such case had arisen before in this
  session): on a confirmed tooling failure, advance deterministically to the next
  index in the same list and retry -- kept mechanical, never a by-hand pick.
- **Index 18 -> `@ashkiani/mongo-logger@1.0.1`.** Tarball sha1-verified against
  registry metadata (`28d824452fcd314a67acbc23c515a5aef9683bba`). Compiled cleanly (26
  methods, 365 calls -- a real, substantial parse, confirming this is content, not
  another tooling failure). **Zero `JSON.stringify`/`util.inspect` calls exist
  anywhere in this package** (`study/blind_r02_mongo_logger/`) -- a genuine, confirmed
  no-candidate result on the crash-safety axis. Because no attacker-controlled
  serializer call site was ever found, the coordinator correctly never invoked the
  taint engine for the size axis either (matching R02's own designed cost-saving
  short-circuit, exercised here for real).

**Honest scope note on this blind run**: it validates the coordinator's crash-axis
fact pipeline (a mechanical, blind, real package correctly produces zero spurious
findings when there is nothing to find) and the correctness of its "skip the taint
engine when there's no candidate" short-circuit, but it does **not** exercise the
corrected, taint-engine-backed size axis against fresh blind evidence, since this
particular draw never reached that branch. That remains open for the next package this
work examines.

## Claims boundary (unchanged)

Nothing in this document is an exploitability, severity, or impact claim.
`reportable=false` on every finding this revision produces, throughout. The motifer
crash-safety adjudication (rejected) and size/structure confirmation (a real,
manually-verified candidate, not demonstrably bounded by anything in motifer's own
code) are serialization-handling and resource-bound classifications only.
