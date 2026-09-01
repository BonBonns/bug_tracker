# SERIALIZE-DOS-R01 -- validation results

**R01's `motifer@26.1.1` blind result below was manually reviewed and found NOT
confirmed as originally framed (both axes emitting a candidate is not itself
confirmation) -- see `R02_RESULTS.md` for the full manual review, the architectural
correction it required (R01's size/structure axis is superseded by R02, which
coordinates the real taint engine instead of approximating it), and R02's own
(separately, mechanically selected) blind package. This document is kept as the
historical record of R01's first-cut validation; `R02_RESULTS.md` is current.**

Standalone, property-local. `reportable=false` on every finding this revision produces
(pipeline integration explicitly deferred -- not wired into any shared provenance,
reachability, staged-enablement, or aggregator module). See `RECONCILIATION.md` for the
full comparison that led to the two-axis design (`crash_dos_classification` /
`size_structure_dos_classification`, never merged).

Frozen implementation hashes (recorded at freeze time, before the blind-package run):
```
b4429f6c8fb257786321d0627b7908caa87eac5f95fe29ea70b86a98ba9a9f9a  serialize_dos_r01.py
937dc64f6d96fd453f02f0ee167ff79d7fa5d23eb01c45bd2b3034e0c26502d9  producers/transform_presence.sc
5502e7dfc6c6c2f1da9a3a97e8820f777edae03f421195bab03b357af085059d  check_serialize_dos_r01.py
```

## 1. Fixture gate

`check_serialize_dos_r01.py`, all 7 fixtures real-Joern-compiled (`fixtures/src/`,
`jssrc2cpg`, this session's Maven-assembled Joern 4.0.608 toolchain -- not hand-authored
TSV): **`SERIALIZE_DOS_R01=10/10`, `PROMOTION_GATE=PASS`**. Covers positive (D1-D2),
guarded-negative where the two axes are documented to disagree (D3-D4, D7), ordinary
negative (D5), and abstention (D6, a detected transform the size axis cannot
structurally resolve).

## 2. Historical evidence: real FXA corpus (`mozilla/fxa`, `customs.js` + `emails.js`)

The exact two real files the taint-engine implementation used for its own real-corpus
evidence (`tchecker-property-adjudicator/fixtures/customs_dos_serialize/corpus-scan/`),
independently recompiled this session and run through this revision's own producers.
Three real `JSON.stringify` call sites found (matches the source exactly):

| site | attacker | bounded | crash axis | size axis |
|---|---|---|---|---|
| `customs.js:75` (`JSON.stringify(requestData)`) | false | false | `SAFE_NOT_ATTACKER_CONTROLLED` | `SAFE_NOT_ATTACKER_CONTROLLED` |
| `emails.js:612` (`{ uid, secret }`) | false | true | `SAFE_NOT_ATTACKER_CONTROLLED` | `SAFE_NOT_ATTACKER_CONTROLLED` |
| `emails.js:227` (`{ uid, secret }`, different enclosing lambda) | true | true | `SAFE_BOUNDED_LITERAL` | `SAFE_BOUNDED_LITERAL` |

**Disclosed limitation, found by this validation, not papered over:** the taint engine's
own real run on this exact corpus reached `OPEN` (unresolved candidate, awaiting
semantic review) on `customs.js:75`'s flow -- because its interprocedural analysis
traces `requestData` back across the call graph to wherever `makeRequest` is invoked.
This revision's crash/size axes are intraprocedural (inherited directly from the reused
`gates/serialize_dos_verdict.py` model, and disclosed as such in its own docstring): a
bare function *parameter*, never re-assigned via a locally-matched attacker pattern
inside `makeRequest` itself, is not detected as attacker-controlled. **This is a real,
confirmed false-negative direction for this revision relative to the taint engine on
this exact real site** -- expected, and explicitly why RECONCILIATION.md preserves the
taint engine's own interprocedural analysis as the deeper-reaching implementation for
that class of case, rather than claiming this revision replaces it.

## 3. Disclosed development package: `errorhandler@1.5.2`

Selected and recorded (`study/disclosed_errorhandler/DISCLOSED_PACKAGE_CHOICE.txt`)
**before** reading its source: a small, real, actively-used Express error-handling
middleware, chosen because rendering error/request detail is a plausible (not
pre-verified) site for this pattern, and not previously used as evidence by either
existing implementation.

Tarball fetched from the npm registry, sha1 verified against registry metadata
(`dd0aa3952eca44aff7c2985e7d246c5932d70444`) before extraction. One real call site
found: `index.js:144`, `JSON.stringify({ error: error }, null, 2)`.

**Result:** `attacker_controlled=false` (the literal `{ error: error }` argument code
does not match any of the request-derived source patterns), `bounded_literal=true`.
**`crash_dos_classification=SAFE_NOT_ATTACKER_CONTROLLED`,
`size_structure_dos_classification=SAFE_NOT_ATTACKER_CONTROLLED`.** A genuine,
honestly-reported true-negative on both axes -- not a candidate.

The implementation was frozen (hashes above) immediately after this result was
recorded, before the blind package was selected.

## 4. Blind package (mechanical selection): `motifer@26.1.1`

Selection procedure, recorded in full **before** any inspection
(`study/blind_motifer/BLIND_PACKAGE_SELECTION.txt`): a live npm registry search
(`keywords:express-middleware`, 20 results, an external non-cherry-picked ranking),
indexed by `int(sha256(serialize_dos_r01.py)[:8], 16) % 20` using the **frozen**
implementation hash from step 3 -- index `8`, package `motifer`.

Tarball fetched, sha1 verified against registry metadata
(`16988e57fc412171ce977332bd1cad4cc18e5783`) before extraction. One real call site
found: `index.js:188`, inside a request-logging middleware's template literal:
`` req.body ? JSON.stringify(req.body) : null ``.

**Result:** `attacker_controlled=true` (`req.body`, directly), `in_try_catch=false`,
`depth_guarded=false`, `uncaught_handler_present=false`, `bounded_literal=false`,
`transform_present=false` (no intervening transform -- `req.body` is passed to
`JSON.stringify` as-is). The enclosing ternary (`req.body ? ... : null`) is a
null-existence check, not a depth/size guard or a try/catch, and is correctly not
modeled as either.

**`crash_dos_classification=CANDIDATE_UNGUARDED_SERIALIZE_DOS`,
`size_structure_dos_classification=CANDIDATE_UNBOUNDED_SERIALIZE_SIZE`.** A real
positive-path candidate on both axes, on a real, live, published npm package, found
through the frozen, mechanically-selected pipeline -- not cherry-picked, not tuned
after the fact (the implementation was already frozen before this package was chosen).

## 5. Claims boundary (load-bearing, unchanged)

Every classification produced by this revision, on both axes, across every fixture and
every real package run, is a **candidate serialization-handling / resource-bound
classification only**. No exploitability, severity, or impact claim is made anywhere in
this document or in the module's own output (`reportable=false` on every finding is the
explicit, structural expression of that boundary -- pipeline integration, and any
reportability decision, is deferred). `motifer`'s finding in particular is a real
CANDIDATE on both axes -- it is not asserted to be a confirmed vulnerability, and no
resource-exhaustion consequence was observed or measured (no runtime test was run in
this revision; only static classification).

## 6. Scope discipline

This work touched only files under `tchecker-research-complete/serialize-dos-r01/`
(new, this session) plus read-only invocations of the existing, unmodified
`tchecker-property-adjudicator/producers/export_serialize_facts.sc`. No file under
ReDoS (`property_configs/redos_complexity.json`, its producers, or its gates),
`gates/serialize_dos_verdict.py` / `gates/gate_serialize_dos.py` (the direct
implementation -- read, never edited), `adjudicate_js.py` or any other
`tchecker-property-adjudicator` producer (read-only), or any `semantic-bucket-pilot/
scanner-v2/` shared provenance/reachability/staged-enablement/aggregator module was
modified.
