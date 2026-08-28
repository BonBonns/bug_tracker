# Accuracy corpus — oracle-grounded yield study (before any model calls)

## Corpus shift (decision)

The frozen **438-case set stays evidence for the routing result only** — those cases
exist *because* TChecker routed them, so no external dataset can supply independent
outcome labels for those exact operations, and hand-labeling 438 arbitrary crypto
writes is weak. It is **not** the accuracy corpus.

The accuracy corpus is built the other way round: start from **already-labeled
buffer-overflow examples with a trustworthy oracle**, run the **frozen** scanner over
them, and keep only cases where TChecker highlights the exact labeled write. The
target is then the **known program outcome**, not a manual judgment.

## Sources (in order of oracle strength)

1. **Magma** — real bugs with exact locations and **executable** bug oracles.
   Strongest, but heavy: needs the fuzzing build system and runtime canaries; treated
   as a **follow-on**, not the pilot.
2. **NIST SARD / Juliet** — paired vulnerable (`bad`) and safe (`good*`)
   buffer-overflow programs with known flaw locations (`/* POTENTIAL FLAW */`,
   `/* FIX */`). Tractable and directly on-pattern; the **pilot** runs here.
   (Reachable in this environment by `git clone` of a public mirror; direct HTTP to
   samate.nist.gov is blocked by the network policy.)
3. **SecVulEval** — real-world statement-level labels. Usable, but dataset-curated,
   **not** an executable oracle, so every included case must be independently checked
   against source before use.

## Strict inclusion rule (all must hold; applied BEFORE any A/B/C answer)

1. The exact **highlighted operation matches the labeled flaw** (same write
   statement, same line, in the flaw function).
2. The vulnerability is specifically a **destination-capacity violation** (write can
   exceed the destination buffer), not an overread, use-after-free, integer bug, etc.
3. A **trustworthy safe counterpart exists** (the paired `good*` variant, or the
   patched revision) that TChecker also highlights at the same write.
4. **TChecker's supplied facts match the source** (declared capacity, write-length
   expression, element type are correct for the code).
5. **Selection occurs before seeing any A/B/C answers** — the matched set is frozen
   and hashed, then model calls run.

## Target (known program outcome)

- vulnerable example (`bad`) → **vulnerable**
- repaired / good example (`good*`, or patched) → **safe**
- `unresolved` remains a legal model answer but **counts as a miss** against the known
  oracle outcome (this is now an *accuracy* target, not the evidence-relative target
  used for the routing set).

## Important structural nuance (Juliet CWE806)

In Juliet `CWE806_*_declare_memcpy/memmove`, the `bad` and `goodG2B` functions have a
**byte-identical sink** — e.g. `memcpy(dest, data, strlen(data)*sizeof(char))` into
`char dest[50]`. They differ only in the **reachable source length** (`data` is a
large BadSource in `bad`, a bounded GoodSource in `good`). So:

- TChecker highlights the **same** write in both, binds `dest[50]` capacity, sees a
  **symbolic** width (`strlen(data)*…`) → routes both to the length-relationship
  bucket. Good — this is exactly the `length_meaning` interface under test.
- The discriminating fact (how long `data` can be) lives in the **function body**,
  which the reference packet's `function_source` already contains. So a correct
  reviewer/model **can** separate vulnerable from safe by reading the source, and
  C's focused length question ("can `strlen(data)` exceed 50?") targets exactly that
  reasoning.

This makes CWE806 a clean test of whether the focused interface improves the
**actual** safe/vulnerable decision on externally-grounded pairs.

## Yield study (this step — no model calls)

1. Clone the suite; select the destination-capacity write CWEs (pilot:
   `CWE121_Stack_Based_Buffer_Overflow / CWE806_*_declare_memcpy|memmove`).
2. Build a flaw index per file (`juliet_flaw_index.py`): the POTENTIAL-FLAW write, the
   fixed-array declaration, and the oracle outcome for each function (`bad` →
   vulnerable; `goodG2B`/`goodB2G` → safe).
3. Run **frozen** V2 over each file (`c2cpg → export_c_cpp_facts_v03.sc →
   normalize_c_cpp_facts_v03.py → oob_runtime_capacity_v2`).
4. **Match**: for each function, does the scanner highlight the exact labeled write,
   with a bound destination capacity, and does the inclusion rule hold?
5. **Count** exact-matched vulnerable/safe pairs. That yield determines whether an
   adequately-powered accuracy experiment is even possible before any model call.

Only after the matched corpus is frozen and hashed do A/B/C calls run, scored against
the known program outcome with the same family-clustered, gaming-resistant machinery
(re-targeted from evidence-reference to oracle outcome).

## Pilot result (real, reproducible)

Frozen pipeline (`c2cpg 4.0.608 → export_c_cpp_facts_v03.sc →
normalize_c_cpp_facts_v03.py → oob_runtime_capacity_v2`) run over a 4-file pilot
(`CWE806_{char,wchar_t}_declare_{memcpy,memmove}_01`):

- **8/8** highlighted operations matched the exact labeled flaw write
  (`memcpy/memmove(dest, data, strlen(data)*…)` at the POTENTIAL-FLAW line), with
  `dest[50]` capacity bound and a symbolic width → all routed to
  **`semantic_relationship_review` (length_meaning)** — the same bucket the A/B/C
  interface tests.
- **4 vulnerable + 4 safe → 4 matched vulnerable/safe pairs** (`juliet_yield.py`).

So the pipeline works on external oracle-grounded inputs and the matched cases land
in the bucket under test.

## Full-scan yield (224 files, frozen pipeline, NO model calls)

Corpus pinned at Juliet mirror commit `f88433e3` (`build_juliet_corpus.py`).
Raw scan facts are frozen in `study/juliet/raw_FROZEN.json`; the clustering audit
below lives in `study/juliet/clustering_sensitivity.json` and is deliberately **not**
frozen as a conclusion until the clustering rule was verified defensible (it now is).

### Raw facts (frozen)

| measure | result |
|---------|-------:|
| files scanned | 224 |
| exact oracle-matched instances | 364 |
| vulnerable / safe instances | 152 / 212 |
| clean after leakage-safe packet construction | 304 (60 leakage exclusions) |
| **undecidable — identical enclosing-function packet on both sides** | **96** |
| **decidable eligible instances** | **208** (100 vuln / 108 safe) |
| model calls | 0 |

The 212 safe vs 152 vulnerable count reflects Juliet files carrying multiple `good*`
mechanisms (`goodG2B`, `goodB2G`, `goodN`) against one `bad`; related instances are
kept together in their flow-pattern family rather than paired independently.

### Clustering sensitivity at three levels (decidable set)

The honest statistical unit is neither the file (pseudoreplication) nor the coarse
generator stratum (over-merge). Three levels are reported; the middle one is the
defensible clustering unit.

| level | families | both-sided | confirmatory both-sided |
|-------|---------:|-----------:|------------------------:|
| generator stratum (element-type × sink) | 4 | 4 | 3 |
| **flow-topology family** (normalized CFG/dataflow skeleton) | **16** | **16** | **8** |
| exact-program family (literals + type/sink kept) | 128 | 4 | 3 |

**Conclusion — yield/pipeline result, not a confirmatory sample.** Under the
defensible flow-topology key, the confirmatory both-sided yield is **8**, below the
≥12 minimum-inference gate → **Juliet remains a pipeline study**, not a powered
accuracy experiment. This is *not* the earlier over-merged "4 templates" figure:
distinct control-flow guard shapes are correctly separated (e.g. `if(V)` vs
`if(V==L)` guard families are distinct), so real flow diversity is preserved — there
simply are not yet 12 *decidable* both-sided flow families in this CWE806 slice.

### Two audits that shaped the count

1. **Storage-class normalization.** Juliet declares the safe helpers `static` while
   the vulnerable `bad` is public. A single `static` token is a declaration
   decoration, not control/data-flow topology, and was splitting every
   vulnerable/safe pair into two flow families. `flow_skeleton` now drops
   storage-class/cv-qualifiers (`static/const/extern/inline/register/volatile/auto`)
   so a pair co-clusters; the exact-program level keeps them. After the fix, all 21
   raw flow families were both-sided.
2. **Decidability filter (part of the inclusion rule).** Co-clustering then exposed
   that Juliet's inter-procedural data-flow variants (`41/44/51-54/65`) place the
   discriminating source-length logic *outside* the sink function, so `bad` and
   `good` neutralize to a **byte-identical** enclosing-function packet — undecidable
   from the packet, and therefore not a valid test. The **96** such instances are
   excluded, leaving **208** decidable and **16** flow families (**8** confirmatory).
   Without this filter the count would spuriously read 12 and appear to meet the gate.

**Collision audit (verifies the clustering).** Every member of each flow family shares
one identical normalized skeleton string (topology genuinely shared, not a hash
artifact), and the largest families separate on real guard structure — confirming the
key neither over-merges distinct topologies nor pseudoreplicates identical ones. The
leakage audit is conservative (any `bad/good/G2B/B2G` substring, `POTENTIAL FLAW/FIX/
OMITBAD/OMITGOOD`, CWE/testcase filenames and include paths, helper names): 60
instances that retained a tell were excluded rather than admitted.

A powered Juliet A/B/C would need many more *distinct decidable* templates: other
CWE-121 sink families (strcpy/strncpy/loop/snprintf, alloca vs declare, different
capacities), other buffer CWEs (122/124), and different destination sizes — or,
better, the real-code sources below.

## Validity caveat (Juliet is synthetic)

Juliet cases are templated: `bad` uses a `BadSource`, `good` a `GoodSource`, in a
recognizable idiom. A model may pattern-match the template rather than reason about
the length relationship. This inflates apparent accuracy and is a known Juliet
limitation. Therefore Juliet is the **pilot / yield** source; **Magma** (real bugs,
executable oracle) is the stronger accuracy source and remains the intended follow-on.
Report Juliet results as such, never as evidence of real-world detection accuracy.
