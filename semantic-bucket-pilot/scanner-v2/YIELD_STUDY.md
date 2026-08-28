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

## Validity caveat (Juliet is synthetic)

Juliet cases are templated: `bad` uses a `BadSource`, `good` a `GoodSource`, in a
recognizable idiom. A model may pattern-match the template rather than reason about
the length relationship. This inflates apparent accuracy and is a known Juliet
limitation. Therefore Juliet is the **pilot / yield** source; **Magma** (real bugs,
executable oracle) is the stronger accuracy source and remains the intended follow-on.
Report Juliet results as such, never as evidence of real-world detection accuracy.
