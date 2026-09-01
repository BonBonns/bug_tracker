# SERIALIZE-DOS-R03 -- the source-occurrence correction

Continues from `R02_RESULTS.md`. This revision exists because R02's coordinator,
correct in architecture, still inherited a real bug from the canonical taint engine's
own discovery step -- "a coordinator cannot correct missing upstream evidence." R03
fixes the upstream evidence itself, with a new producer revision, never by patching
the coordinator around the gap.

## 1. The bug, precisely

`setup_candidate.sc` (frozen, untouched) selects the sink via
`cpg.call.name("stringify").headOption` and the source via
`cpg.call.codeExact(srcPattern).headOption` -- both single, arbitrary "first" picks in
whatever order Joern's traversal returns. On the real `motifer@26.1.1` package,
`req.body` appears twice at the same call site: once as a ternary's condition, once as
the argument actually passed to `JSON.stringify`. `.headOption` picked the condition
(which structurally has zero flow to the sink), so the automated taint-engine run
reported `NO_FLOW` even though the argument's own occurrence -- id-identical to the
sink's own argument -- has the most direct flow shape possible. R02's coordinator,
however architecturally sound, had no way to see past this: it only reads whatever
`evidence_final.json` the taint engine produces.

## 2. The fix: `producers/setup_candidate_multisource.sc`

A new producer (the frozen `setup_candidate.sc` is untouched and still runs exactly
as before). Full rationale in its own docstring; summary:

- Enumerates **every** matching sink call and **every** matching source occurrence --
  never `.headOption` on either side.
- Computes a real Joern dataflow (`reachableByFlows`) for **every** (sink, source)
  pair in the resulting cross-product -- the dataflow engine decides which pairs have
  a real flow; nothing is guessed or ranked.
- Writes only the pairs with a real flow into the **same legacy schema**
  `setup_candidate.sc` always wrote (`source_facts.tsv` / `propagation_relations.tsv`
  / `transform_identity.tsv`). This means the **frozen**
  `export_property_propagation.sc` (already loops over every distinct row, never
  assumed to be exactly one) and `adjudicate_js.py` (already does a documented
  per-sink "multi-origin existential join") run **completely unmodified**
  downstream -- the fix is entirely upstream, at discovery.
- Also writes a new, node-identity-preserving `multisource_evidence.tsv`: every
  (sink, source) pair **considered**, flowing or not, keyed by each side's real Joern
  node id -- two occurrences with byte-identical `.code` text are never merged into
  one record.

## 3. Validation: 9 required controls, all real-Joern-compiled

`check_setup_candidate_multisource.py`, **`SETUP_CANDIDATE_MULTISOURCE=10/10`**
(9 controls, M1 checked twice -- the pattern discovery and the frozen downstream
resolution). Full detail in that gate's own docstring; headline results:

| control | fixture | result |
|---|---|---|
| first no, second yes | `ms-first-no-second-yes` (motifer's exact shape, minimized) | condition `has_flow=false`, argument `has_flow=true`, frozen downstream resolves `ESTABLISHED`/`RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` |
| dedup at one sink | `ms-both-same-sink` | two distinct flowing source ids, ONE `evidence_final.json` (adjudicate_js.py's own existing multi-origin join) |
| different occurrences, different sinks | `ms-different-sinks` | two functions, two sinks, each source flows only to its own sink (correct cross-function isolation) |
| unrelated earlier occurrence | `ms-unrelated-earlier` | an occurrence isolated inside a different, uninvoked closure has no flow; the real, later, direct occurrence does |
| no occurrence reaches a sink | `ms-no-flow` | `has_flow=false`, `source_facts.tsv` empty, no evidence produced (matches this session's "skip when there's nothing to check" convention) |
| identical text, distinct identity | (M1's own evidence) | two rows, same `.code` text, different node ids, both preserved |
| **real motifer reproduces automatically** | the real `@8crafter`... no -- the real `motifer@26.1.1` package | `ESTABLISHED`/`RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS`, **zero manual override needed** |
| historical interprocedural positive, unregressed | `demo_member_transform.js` | `OPEN`/`CANDIDATE_OPEN`, unchanged |
| historical fixed/negative, unregressed | `demo_lookup_falsepos.js` | no flow, empty `source_facts.tsv`, unchanged |

## 4. R03 the coordinator: identical shape, corrected evidence source

`serialize_dos_r03.py` is architecturally identical to `serialize_dos_r02.py` (own
docstring has the full rationale) -- `crash_dos_classification` still reused verbatim
from `gates/serialize_dos_verdict.py`, untouched; `size_structure_dos_classification`
still a pure map of the real taint engine's own disposition, never computed here. The
**only** change is which pipeline run produced that disposition: the corrected
`setup_candidate_multisource.sc` run, not the old `setup_candidate.sc` run.

`check_serialize_dos_r03.py`, **`SERIALIZE_DOS_R03=10/10`**:
- All 7 of R01/R02's fixtures reproduce **identical** results to R02 (T1-T7) -- proof
  the correction is a safe, non-regressing drop-in for every case that didn't hit the
  bug.
- **T8, motifer: the case that changes.** `crash_dos_classification` stays
  `CANDIDATE_UNGUARDED_SERIALIZE_DOS` (automated, unchanged -- the crash-safety
  analyzer was not touched by this correction). `size_structure_dos_classification` is
  now **`CANDIDATE_UNBOUNDED_SERIALIZE_SIZE`**, sourced from a real
  `RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` disposition -- under R02's coordinator,
  fed by the old `setup_candidate.sc`, the automated result here would have been
  `SAFE_NO_STRUCTURAL_FLOW` (the taint engine's tool artifact). **This is why the
  canonical evidence changed and this revision is published as R03**, per instruction,
  rather than folded quietly into R02.

Per instruction, motifer is one of the fixtures frozen here as a **development
regression** (not a fresh blind draw) -- both R01's 7 fixtures and motifer are
re-validated and locked in as R03's own regression baseline.

**Manual adjudication is not re-encoded here.** R03's automated
`crash_dos_classification` for motifer is still `CANDIDATE_UNGUARDED_SERIALIZE_DOS` --
the crash-safety analyzer has no model of Express's dispatch-layer catch boundary, and
this correction never touched it. The real adjudication (REJECTED, per
`MOTIFER_MANUAL_REVIEW.md`) and the four-tag size/structure record
(`SIZE_STRUCTURE_FLOW_CONFIRMED` / `PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED` /
`EXTERNAL_CONFIGURABLE_BOUND_PRESENT` / `RESOURCE_CONSEQUENCE_NOT_ESTABLISHED`) remain
documented separately, exactly as R02 established -- a mechanical coordinator's job is
to report what the canonical tools say, not to silently substitute a human judgment
call for their output.

Frozen implementation hashes:
```
b4de871f995c47d5444419cebc2140d9a12041d366972070ac1eb9ff21ac3548  producers/setup_candidate_multisource.sc
39e4765e9649fae1463bd257f7525c3774e39bd6687a200476d8a1cbae8d09b4  check_setup_candidate_multisource.py
dfdd4e4719f5c4ae6b8c4826ed29d7811438b8f95c094a380946d35b6a69a41b  serialize_dos_r03.py
6b6fb929140c7db43810dda69a75a9cc3661bb0cb95b41d4043e59f71dfa4d03  check_serialize_dos_r03.py
```

## 5. R03 blind package (mechanical selection)

`@ashkiani/mongo-logger` (R02's blind draw) remains a valid negative but, having zero
serialization call sites at all, gave no positive-path portability evidence for the
corrected multisource producer. Per instruction, a new package was mechanically
selected this round specifically to exercise real serializer call sites.

Procedure recorded in full before any inspection:
`study/BLIND_PACKAGE_SELECTION_R03.txt`. Same index formula against a live npm
registry search, a third distinct keyword (`keywords:http-logger`) from R01's and
R02's draws. **Correction made to the declared advance condition before fetching the
selected package**: since this round's explicit goal is a package with at least one
real serialization site, the pre-registration was amended (before inspection) to also
advance to the next index on a *confirmed-empty* result (zero
`JSON.stringify`/`util.inspect` calls, verified by the real producer, not a grep
guess), in addition to R02's original tooling-failure advance condition.

- **Index 3 -> `@rasla/logify@5.2.2`.** Tarball sha1-verified against registry
  metadata (`10fb26f52de55a7373da5711defebc144e33a494`). Ships a large, single-file
  bundled `dist/index.js` (19,572 lines -- bundles vendored dependencies, including
  what appears to be Elysia framework internals). Compiled cleanly under an extended
  timeout: **2,493 methods, 48,100 calls** -- by far the largest real CPG this
  property has processed, confirming the corrected pipeline scales past small
  fixtures. **68 real, structurally-recognized `JSON.stringify`/`util.inspect` call
  sites found** (`study/blind_r03_logify/`) -- satisfying the letter of both the
  instruction and this round's own pre-registered advance condition, so no further
  advance was applied.

**Honestly disclosed**: all 68 sites classify `SAFE_NOT_ATTACKER_CONTROLLED` on both
axes (values like `val`, `v`, `seed`, `datum` -- parameters/locals, no literal
`req.*`-style pattern present in this bundle). This is now the **third** real npm
package in a row (after mozilla/fxa's `customs.js` and `@sonatel-os/juf-xpress-logger`)
where the crash-DoS producer's textual, intraprocedural attacker-source heuristic
misses a value that arrives as an already-abstracted function parameter rather than a
literal `req.body`-shaped accessor -- a real, recurring, disclosed limitation, not a
one-off. This round's blind package is genuine positive-**path** portability evidence
(a large, real, previously-unseen file processed correctly end-to-end through the
corrected pipeline, 68 real sink sites all correctly triaged) without being a positive
attacker-controlled **candidate** -- the two are not the same claim, and only the
former is made here.

## Claims boundary (unchanged)

Nothing in this document is an exploitability, severity, or impact claim.
`reportable=false` on every finding, throughout, both fixture groups and the blind
package. Motifer's crash-safety adjudication (rejected, per manual review) and its
four-tag size/structure record are unchanged by this revision -- R03 only corrects
which automated evidence the coordinator's `size_structure_dos_classification` is
built from.

## 6. Scope and next steps

Touched only `tchecker-research-complete/serialize-dos-r01/` (new files: the
multisource producer, its gate, `serialize_dos_r03.py`, its gate, this document, and
`study/` evidence). No ReDoS file, no `gates/serialize_dos_verdict.py` or
`gates/gate_serialize_dos.py`, no other `tchecker-property-adjudicator` producer or
`adjudicate_js.py`, and no `semantic-bucket-pilot/scanner-v2` shared pipeline module
was modified -- `setup_candidate.sc` itself remains byte-for-byte frozen. Branch stays
isolated (`feature/serialize-dos-r01`), not rebased onto `develop`, until the ReDoS
session finishes **and** this occurrence bug is resolved -- both conditions are now
met for the bug; the branch still waits on the former before any shared
provenance/applicability/reachability/aggregation wiring.
