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
in the bucket under test. The full `CWE806_declare_memcpy|memmove` set is 224 files
(56 variants × char/wchar × memcpy/memmove); scaling the scan gives the real yield.

## Validity caveat (Juliet is synthetic)

Juliet cases are templated: `bad` uses a `BadSource`, `good` a `GoodSource`, in a
recognizable idiom. A model may pattern-match the template rather than reason about
the length relationship. This inflates apparent accuracy and is a known Juliet
limitation. Therefore Juliet is the **pilot / yield** source; **Magma** (real bugs,
executable oracle) is the stronger accuracy source and remains the intended follow-on.
Report Juliet results as such, never as evidence of real-world detection accuracy.
