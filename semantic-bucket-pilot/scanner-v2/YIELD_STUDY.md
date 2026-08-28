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
| **packet-insufficient — outcome not identifiable from the sink-function packet** | **96 (31.6%)** |
| **packet-identifiable eligible instances** | **208** (100 vuln / 108 safe) |
| model calls | 0 |

The 212 safe vs 152 vulnerable count reflects Juliet files carrying multiple `good*`
mechanisms (`goodG2B`, `goodB2G`, `goodN`) against one `bad`; related instances are
kept together in their flow-pattern family rather than paired independently.

### Two questions, two populations (no cherry-picking)

The 304 clean instances split into two populations serving two *different* questions.
The split is **`packet_identifiability`**, not "decidability" — the programs are not
inherently undecidable; their outcome is simply not identifiable from the *current
packet*, and caller/path expansion may recover it.

- **Packet-identifiable (208).** Vulnerable and safe versions produce distinguishable
  packets, so a reviewer/model has the evidence to decide. These are eligible for the
  conditional A/B/C **outcome-accuracy** analysis — the question *can B or C reason
  better when the necessary evidence is present?*
- **Packet-insufficient (96 / 304 = 31.6%).** Vulnerable and safe versions neutralize
  to a **byte-identical** packet: the decisive source-length path lives in callers or
  other functions the sink-function packet **omitted** (Juliet's interprocedural
  variants `41/44/45/51-54/63-68`). These are **retained**, not discarded, as a
  **coverage/routing failure population** answering the *other* question — *did
  TChecker include the necessary path evidence in the packet?* They are excluded from
  A/B/C accuracy (including them would measure missing context, not the C-vs-B
  interface), and their correct **evidence-relative** response is
  `unresolved` / `additional_context_required`.

**This is itself a major result.** Nearly one-third of these CWE806 cases cannot be
judged from the sink-function packet because the decisive path is interprocedural —
directly the "missing paths/context" problem, quantified. It calls for
interprocedural / path-context packet expansion, and is reported (not hidden) in
`study/juliet/clustering_sensitivity.json` under `packet_insufficient_population`.

### Clustering sensitivity at three levels (packet-identifiable set)

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
≥12 minimum-inference gate → **Juliet is presently a pipeline and missing-context
study**, not a powered confirmatory accuracy study. This is *not* the earlier
over-merged "4 templates" figure: distinct control-flow guard shapes are correctly
separated (e.g. `if(V)` vs `if(V==L)` guard families are distinct), so real flow
diversity is preserved — there simply are not yet 12 *packet-identifiable* both-sided
flow families in this CWE806 slice.

**Honest Stage result (one place):**
- 304 sanitized instances.
- 96 packet-insufficient cases retained for the missing-context evaluation.
- 208 packet-identifiable cases eligible for conditional A/B/C accuracy.
- Only 8 confirmatory, both-sided topology families remain, below the 12-family gate.
- Controlled packet expansion (structure-only) recovers *sufficient length evidence*
  for 40/96 (41.7%) of the missing-context cases — all 40 establish write-length,
  capacity, and their relationship — but this is 1 genuine flow family → 9 confirmatory,
  still < 12.
- Therefore Juliet is presently a pipeline and missing-context study, not a powered
  confirmatory accuracy study.

### Two audits that shaped the count

1. **Storage-class normalization.** Juliet declares the safe helpers `static` while
   the vulnerable `bad` is public. A single `static` token is a declaration
   decoration, not control/data-flow topology, and was splitting every
   vulnerable/safe pair into two flow families. `flow_skeleton` now drops
   storage-class/cv-qualifiers (`static/const/extern/inline/register/volatile/auto`)
   so a pair co-clusters; the exact-program level keeps them. After the fix, all 21
   raw flow families were both-sided.
2. **Packet-identifiability partition (part of the inclusion rule).** Co-clustering
   then exposed that Juliet's inter-procedural data-flow variants
   (`41/44/45/51-54/63-68`) place the discriminating source-length logic *outside* the
   sink function, so `bad` and `good` neutralize to a **byte-identical**
   enclosing-function packet — the outcome is not identifiable from the packet, so it
   is not a valid A/B/C test (but the program is not undecidable; caller expansion may
   recover it). The **96** such instances are moved to the retained missing-context
   population, leaving **208** packet-identifiable and **16** flow families (**8**
   confirmatory). Without this partition the count would spuriously read 12 and appear
   to meet the gate.

**Collision audit (verifies the clustering).** Every member of each flow family shares
one identical normalized skeleton string (topology genuinely shared, not a hash
artifact), and the largest families separate on real guard structure — confirming the
key neither over-merges distinct topologies nor pseudoreplicates identical ones. The
leakage audit is conservative (any `bad/good/G2B/B2G` substring, `POTENTIAL FLAW/FIX/
OMITBAD/OMITGOOD`, CWE/testcase filenames and include paths, helper names): 60
instances that retained a tell were excluded rather than admitted.

A powered Juliet A/B/C would need many more *distinct packet-identifiable* templates: other
CWE-121 sink families (strcpy/strncpy/loop/snprintf, alloca vs declare, different
capacities), other buffer CWEs (122/124), and different destination sizes — or,
better, the real-code sources below.

## Controlled packet expansion — the missing-context experiment (`juliet_packet_expansion.py`)

Does adding the **minimal relevant caller / data-flow path** make the 96
packet-insufficient cases identifiable? Two packets per case — `baseline`
(sink-function body only) and `expanded` (baseline + the minimal caller chain that
determines the sink's source length) — with **context selection driven purely by the
call graph and parameter/argument indices in the CPG, never Juliet's safe/vulnerable
label** (the selection survives renaming; the oracle is read only when measuring
recovery). A case *recovers* if, after expansion and the same leakage-safe
neutralization, its packet is no longer byte-identical to an opposite-oracle packet.

| measure | result |
|---------|-------:|
| packet-insufficient cases | 96 |
| structurally distinguished (safe/vuln packets differ after expansion) | 40 |
| **fully recovered (sufficiency-checked)** | **40 (41.7%)** |
| structurally-distinguished-only (differ but bound not established) | 0 |
| unexpandable by minimal parameter-passing expander | 56 (46 no inbound-parameter source, 10 no caller) |
| model calls | 0 |

**Sufficiency check — distinguishable is not the same as identifiable.** Expansion
proving the safe and vulnerable packets are no longer identical is necessary but not
sufficient; the added frame must actually *decide the bound*. For each of the 40, three
quantities are extracted **structure-only** (no oracle): the destination **capacity**
(V2 `element_count` = 50), the source **write length** (the concrete `memset` fill
length traced up the caller chain — `100-1` = 99 vs `50-1` = 49, so
`strlen(data)` = that length under the fill-then-null idiom), and their **relationship**
(99 > 50 → *exceeds*; 49 < 50 → *within*). All **40/40** establish all three (0 remain
merely structurally distinguished). That the *exceeds/within* verdict matches the known
`bad`/`good` outcome is a cross-check, not a leak — selection and extraction never read
the label.

**Coverage result.** Minimal, structure-only caller context recovers **sufficient
length evidence** for **41.7%** of the missing-context cases — the source-length
`memset` a sink-only packet omits sits one call edge up, and expansion pulls exactly
that frame. Recovered variants are Juliet's argument-passing data-flow cases
(`41/51-54`). The **56** unexpandable cases route their source length through globals /
pointers / structs (variants `44/45/63-68`), beyond a minimal parameter-passing
expander — the natural target for a richer slice.

**It does *not* by itself meet the 12-family gate.** Clustered honestly, recovery adds
only **1** genuine flow-topology family (confirmatory both-sided **8 → 9**, still < 12).
A naive count reads 8 → 12 and appears to pass — but that is **interprocedural
pseudoreplication**: variants `51/52/53/54` are *one* decision path with 1/2/3/4
identical pass-through forwarder frames (`void f(T* d){ g(d); }`), differing only in
hop count. The expander therefore *traverses* inert forwarders to reach the
length-determining frame but excludes them from the packet (the "minimal **relevant**
path"), so forwarding depth does not split into distinct families. Counting depth as
topology would have spuriously met the gate — the same over-merge/pseudoreplication
discipline applied one level up.

**Net (defensible result).** Structure-driven caller expansion recovered *sufficient*
length evidence for **40 of 96** previously packet-insufficient cases — a **41.7%
coverage improvement** — representing **one** independent interprocedural flow topology.
It is a genuine coverage gain and a proof that interprocedural evidence is the right
lever, but it does not convert this CWE806 slice into a powered confirmatory accuracy
sample (confirmatory both-sided **8 → 9**, still < 12). Reaching 12 independent families
is better served by broadening to **other CWEs / genuinely different length-flow
patterns** than by counting additional pass-through variants. Reported in
`study/juliet/packet_expansion.json`.

## Broadening to independent families — pre-registered multi-suite scan (`broaden_*.py`)

Pre-registered **before** any yield (`PREREGISTER_BROADENING.md`, `predeclared_suites.py`):
same fixed property (write length exceeds **destination** capacity, via a copy
operation), scanned across every present in-scope suite — `CWE121` (stack) and `CWE122`
(heap), which contain the nested `CWE805`/`CWE806` idioms; `CWE805`/`CWE787` have no
top-level C dir here; `CWE124/126/127/680` excluded by property. Same 8-step pipeline,
same seeds/gate, zero model calls.

**Executed in full (did not stop at three):** 6,428 predeclared copy-idiom `.c` files
scanned in 13 batches → **1,336 eligible** (exact copy sink, POTENTIAL-FLAW line,
symbolic width, `semantic_relationship_review`, leakage-clean) → **1,032
packet-identifiable**. Per suite: CWE121 416, CWE122 616 identifiable.

**Clustering sensitivity (confirmatory both-sided families):**

| clustering level | confirmatory | vs gate 12 |
|------------------|-------------:|:----------:|
| property signature (dest-capacity mechanism × write-length shape) — *property-faithful* | 2 | below |
| guard-collapsed dataflow topology | 26 | (meets) |
| full flow-topology (guards kept; pre-registered key) | 24 | (meets) |

**Honest verdict: 2 genuine capacity-provenance families, gate NOT met.** The raw
flow-topology key reads 24,
but that is inflated by variation **superficial to the destination-capacity property**:

- families with **byte-identical** capacity + length + sink lines split only by opaque
  reachability guards (`if(V)` / `if(V())` / `if(V==L)`) — collapsing guards leaves the
  count high (26), so guards are not even the main inflation;
- source-side variation that does not touch the property: source-buffer allocation
  method (`declare` / `alloca` / `malloc`) and subtype label;
- many CWE122 files overflow a stack `dest[50]` with a heap-allocated *source* — those
  collapse into the stack family (same destination reasoning); but CWE122 files with a
  genuine **heap destination** are a distinct family (see below), so CWE122 is not
  uniformly a stack duplicate.

The property-faithful key gives both-sided signatures, but a signature is only a
**genuine capacity-establishing family** if the scanner actually **established the
destination capacity** — read from the **internal extent facts**, not the packet's
`element_count` field (which is only the V2 **stack-array** representation; it is `None`
on heap destinations *even when* the heap extent is established). Capacity is established
by **two producers with distinct provenance**: V2 `stack_fixed_array` and V1
`heap_direct_allocation` (`compute_allocation_extents()`, `ESTABLISHED`, provenance
`direct_allocation`).

| property signature (capacity provenance × length shape) | n | both-sided | capacity established | genuine? |
|--------------------|--:|:----------:|:--------------------:|:--------:|
| `stack_fixed_array \| strlen(src)*sizeof` | 624 | yes | **624/624** | **yes** |
| `heap_direct_allocation \| (strlen(src)+1)*sizeof` | 156 | yes | **156/156** | **yes** |
| `heap_direct_allocation \| strlen(src)*sizeof` | 252 | no (all vuln) | 252/252 | no |

**Correction — heap capacity IS bound.** An earlier draft read the packet's
`element_count` and wrongly concluded "0/384 heap, CWE122 adds zero families." That field
is the stack-array representation; the level-3 check against `compute_allocation_extents()`
(`heap_extent_check.py`) finds **496 heap extents `ESTABLISHED`** (408 among identifiable
dests) with `direct_allocation` provenance. The packet builder simply never exposed the
heap capacity field — the capacity decision exists internally, in a different producer.

**Genuine independent capacity-establishing families = 2** —
(1) `stack_fixed_array` + symbolic `strlen*sizeof` (the CWE806 baseline), and
(2) `heap_direct_allocation` + `(strlen+1)*sizeof` (CWE122 — a genuine **second
capacity-provenance** family, different producer and evidence). So broadening added
**one** genuine new capacity-provenance family; the count (**2**) still does not approach
the 12 gate. Reaching 12 requires further distinct capacity/length **decision structures
the scanner can establish** — integer-arithmetic capacity, loop-computed length, index
writes — or real-world code (**Magma**), not more symbolic-`strlen` copy variants.
Reported in `study/juliet/broaden_families.json` and `study/juliet/heap_extent_check.json`.
The 56 CWE806 packet-insufficient cases remain a documented future population (not chased).

### Two DIFFERENT family counts — provenance vs review topology (`review_topology.py`)

Scanner evidence-provenance and reviewer proof-obligation are different questions and are
reported separately:

- **`capacity_provenance_families = 2`** — stack capacity from an array declaration
  (`stack_fixed_array`, V2) vs heap capacity from a `malloc` extent
  (`heap_direct_allocation`, V1). This is a scanner-evidence distinction.
- **`independent_review_topologies = 2`** keeping the off-by-one, **= 1** when the `+1`
  null-terminator is treated as the same reasoning. Both *both-sided* obligations reduce
  to **"does `strlen(source)` fit within the known element capacity?"** — the heap family
  differs only by a `+1` and by provenance (abstracted at the review level). So CWE122
  does **not** add an independent reviewer reasoning family, even though it is a genuine
  second scanner-provenance family.

| proof obligation (sizeof(T) preserved) | vuln | safe | both-sided | for A/B/C |
|----------------------------------------|-----:|-----:|:----------:|:---------:|
| `STRLEN vs CAP_elems [same_sizeof]` (stack strlen-fits-capacity) | 300 | 324 | yes | usable |
| `STRLEN+OFF vs CAP_elems [same_sizeof]` (heap, +1 off-by-one) | 76 | 80 | yes | usable |
| `CONST vs CAP_elems [same_sizeof]` (concrete count) | 210 | 0 | no | one-sided |
| `CONST vs CAP_bytes [write_sizeof_vs_cap_bytes]` (CWE131 byte/element **mismatch**) | 42 | 0 | no | one-sided |

The genuinely *different* reasoning — the CWE131 **byte/element unit mismatch**
(`malloc(10)` bytes vs `10*sizeof(int)`) — is present but **one-sided** (no safe
counterpart survives inclusion), so it cannot yet serve as a both-sided A/B/C family.

**Packet builder now exposes heap capacity.** `capacity_expr()` assembles the
`established_capacity` fact for *both* producers — heap gets `size_expression`
(e.g. `(10+1)*sizeof(wchar_t)`), `element_count` (coefficient only), `element_width`
(`sizeof(T)` kept **symbolic** — no ABI byte size assumed), and provenance — so B and C
would receive the heap capacity the way they receive `element_count` for stack. Validated
**1008/1032** independently against the source (`malloc`/declaration re-parsed and matched);
the rest are `alloca`/edge cases. Only after this exposure can CWE122 count toward an A/B/C
sample — internally knowing the capacity is not enough if the packet omits it.

### Heap denominator funnel (`reconcile_heap_funnel.py`) — no silent attrition

- **496** established heap extents — eligible oracle ops (semantic route) whose
  `(function, dest)` has an `ESTABLISHED` heap extent and no stack `element_count`.
- **−72** residual-leakage drops (the conservative sanitizer rejects any packet that still
  carries an oracle tell) → **424** extracted heap records. *All* of the 496→424 loss is
  leakage; every other inclusion filter dropped 0 for heap.
- **−16** packet-insufficient (byte-identical bad/good packet) → **408** packet-identifiable
  heap destinations. Reported in `study/juliet/heap_funnel.json`.

### Two pre-Magma audits

**CWE131 safe-side attrition — legitimate one-sidedness (`cwe131_safeside_audit.py`).**
The byte/element-mismatch obligation was one-sided (42 vuln, 0 safe); tracing every
expected safe counterpart through the six stages (source → copy op → facts → producer
status/reason → route → sanitizer/inclusion) shows the safe side is *resolved*, not lost:
**72 safe cases route to `deterministic_complete`**. The safe fix allocates
`malloc(10*sizeof(int))`, whose capacity expression **equals** the `10*sizeof(int)` write
width, so the scanner proves no overflow and correctly never sends it for review; the bad
side (`malloc(10)` bytes vs `10*sizeof(int)`) is `capacity_relation_not_established` and
routes to `semantic_relationship_review`. This is **outcome #1 — the asymmetry is
legitimate** (the scanner solves the safe cases), not a pipeline artifact. No inclusion
criteria were loosened to manufacture balance. Reported in
`study/juliet/cwe131_safeside_audit.json`.

**24 / 1032 capacity validations that did not confirm — all expected exclusions.** Every
one is `dest_is_parameter | no_alloc_in_packet`, vulnerable, `heap_direct_allocation`:
interprocedural cases where the sink receives `data` as a parameter and the `malloc` is in
the caller, so the extent was established by cross-function **propagation**
(`propagated_call:` provenance) and the allocation is simply out-of-packet — nothing to
validate packet-locally. **0 invalid, 0 unresolved, 24 expected exclusions.** (Exposing
these to a reviewer would need the same packet expansion as the packet-insufficient
population.) Recorded as `capacity_unvalidated_classification` in
`study/juliet/review_topology.json`.

### Juliet conclusion → Magma

Juliet's many files collapse to roughly **one** independent reviewer question ("does
`strlen(source)` fit within the known capacity"); its genuinely different obligation
(byte/element mismatch) is legitimately one-sided. More Juliet variants are unlikely to
add the missing topological diversity. The next source is **Magma** — real, oracle-backed
bugs — for genuinely independent review topologies.

### Batch-invariance control (`batch_invariance.py`)

Because the scan ran in 500-file batches, we proved batching does not change scanner
results: two adjacent completed batches (batch5, batch6) scanned separately vs a combined
**1000-file** rescan, comparing every oracle-bearing operation's candidate status, reason
codes, route, capacity, write-length (`width_expr`), element type, dest, unresolved
property, and uncertainty. The key is `(file, line, dest, site_ordinal)` with an
**asserted-unique** invariant — `(file, line)` alone is not assumed unique since multiple
sink calls can share a line (here 0 collisions, assertion passes).

- **All 749 operations byte-identical** (546 eligible), 0 diffs, 0 oracle mismatches, no
  membership change. **PASS.**
- The only artifact of combining files is c2cpg's cosmetic `<duplicate>N` suffix on reused
  helper names (`goodG2B`/`bad`/`printLine`), whose N differs in a larger CPG. It changes
  no compared field, preserves the bad/good oracle, and is erased by neutralization — so
  it cannot affect the flow-family analysis. Keyed on `(file, line)` it is invisible; the
  arbitrary-batch-size split is therefore result-invariant and grouping by call-component
  was not needed. Reported in `study/juliet/batch_invariance.json`.

## Validity caveat (Juliet is synthetic)

Juliet cases are templated: `bad` uses a `BadSource`, `good` a `GoodSource`, in a
recognizable idiom. A model may pattern-match the template rather than reason about
the length relationship. This inflates apparent accuracy and is a known Juliet
limitation. Therefore Juliet is the **pilot / yield** source; **Magma** (real bugs,
executable oracle) is the stronger accuracy source and remains the intended follow-on.
Report Juliet results as such, never as evidence of real-world detection accuracy.
