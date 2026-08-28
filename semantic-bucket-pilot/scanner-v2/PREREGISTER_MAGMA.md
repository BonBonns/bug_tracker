# Pre-registration — Magma accuracy source (frozen BEFORE any model call / usable-yield claim)

Juliet's many files collapsed to ~1 independent reviewer question (`does strlen(source)
fit within the known capacity`); its one genuinely different obligation (byte/element
mismatch) is legitimately one-sided. Magma supplies **real, oracle-backed bugs** in real
codebases — the stronger source for genuinely independent review topologies.

## Fixed property (unchanged)

> **Does the write length exceed the destination capacity?**

Only Magma bugs whose canary encodes this relation at a **write** are eligible.

## Why Magma fits

Each Magma bug is a patch that adds, at the exact bug site:
- `#ifdef MAGMA_ENABLE_FIXES … <bounds check> … #endif` — compiled IN ⇒ **safe**, OUT ⇒
  **vulnerable**. Same file, same site: a real vulnerable/safe **pair**.
- `#ifdef MAGMA_ENABLE_CANARIES MAGMA_LOG("%MAGMA_BUG%", <condition>); #endif` — an
  **executable oracle**: the condition is TRUE exactly when the bug triggers.

Example (TIF002, `libtiff/tif_pixarlog.c`): canary `(tmsize_t)sp->stream.avail_out >
sp->tbuf_size` — write length vs destination capacity, a real symbolic length↔capacity
relation of the class the `length_meaning` A/B/C interface tests.

## Inclusion rule (all must hold; frozen before usable-yield is claimed)

1. **Property**: the canary condition is a comparison of a length/index/offset/count term
   against a capacity/size/bound term at a **write** (not a read overrun, integer-overflow
   of a scalar, null/type/state check, or float validation).
2. **Fetch pinned source**: `targets/<t>/fetch.sh` clones the upstream repo at its pinned
   commit; the bug patch is applied.
3. **Two variants per bug**: vulnerable = FIXES undefined; safe = FIXES defined. Both are
   the same source at the same site.
4. **Strip the oracle from the packet**: the `MAGMA_LOG("%MAGMA_BUG%", …)` canary states
   the vulnerability condition verbatim and MUST be removed (as Juliet's `POTENTIAL FLAW`
   is), along with `MAGMA_ENABLE_*` markers, before any packet is built. The safe/vuln
   label comes only from which variant was compiled, tracked in metadata, never in the
   packet.
5. **Scanner highlight**: the frozen scanner (`c2cpg → export → normalize →
   oob_runtime_capacity_v2`) must highlight the **write at the canary site** and bind a
   destination capacity (stack array, heap extent, or a fixed `sizeof` buffer).
6. **Route**: that operation routes to `semantic_relationship_review` (the length_meaning
   bucket) — i.e. the length↔capacity relation is symbolic, not deterministically closed.
7. **Both sides present and packet-identifiable**: vulnerable and safe packets are
   distinguishable after oracle-stripping; capacity + write length are established (heap
   extents read from the internal facts, `sizeof(T)` kept symbolic — no ABI byte size).

## Reporting commitments

- Report the **usable yield** honestly: canaried bugs → eligible-by-property → scanner
  highlights the write → routes length_meaning → both-sided packet-identifiable, with each
  drop itemized (as the Juliet heap funnel is).
- Cluster usable cases by **proof obligation / review topology** (not by target or CWE),
  and report `capacity_provenance_families` and `independent_review_topologies` separately.
- Not every eligible canary site is a scanner-recognized copy sink (e.g. TIF002's write is
  a `zlib inflate`, not a `memcpy`); expect usable yield < eligible. Direct fixed-buffer
  writes (`num > sizeof(ebcdic_buf)`, `length > sizeof(vheaTab)`,
  `loop_count > ARRAY_LEN(loops)`) are the cleanest and are the pilot targets.
- No model calls until a usable, oracle-grounded, family-clustered sample is frozen.

## Eligible bug catalog (this mirror)

Machine-readable: `study/magma/bug_catalog.json` (classifier over all 116 canaried bugs).
Eligible destination-capacity write bugs: **11**, across 6 real targets (PNG/SND/TIF/SSL/
PHP/PDF); 3 are the cleanest fixed-`sizeof`/`ARRAY_LEN` capacity form. This is a
conservative count (the classifier errs toward exclusion).
