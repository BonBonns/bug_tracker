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

## A canary match is a CANDIDATE, not an eligible case

A canary encodes a *trigger condition*; it need not correspond to a TChecker-supported
destination write. Counting canary matches as eligible would overstate the yield. Every
bug advances through the staged manifest below and is `eligible` only when ALL eight
conditions hold. No yield is counted before this rule is frozen (it is, here).

## Eligibility rule (all eight must hold; FROZEN)

1. **Configurations**: the bug has a vulnerable AND a fixed configuration
   (`MAGMA_ENABLE_FIXES` present in the patch); vulnerable = FIXES undefined, safe = FIXES
   defined, same source at the same site.
2. **Canary → write mapping**: the canary maps, edge by edge (canary condition → underlying
   state → the actual write/index operation → destination), to a real
   **destination-writing** operation — not merely a trigger predicate.
3. **Property**: the relevant property is a **write extent or index exceeding destination
   capacity** (not a read overrun, scalar integer-overflow, null/type/state check, or float
   validation).
4. **Scanner recognition**: TChecker recognizes that **exact** write/index operation
   (standard sink, library copy alias, or index write) at the mapped site.
5. **Evidence**: destination capacity AND write-length/index evidence are **established or
   explicitly unresolved** (heap extents read from internal facts; `sizeof(T)` kept
   symbolic — no ABI byte size assumed). An out-of-packet (propagated/caller) fact is NOT
   packet-validated: include the caller allocation/provenance in the packet, or exclude the
   case — never present it as if locally established.
6. **Leakage-safe packet**: canary code, the `%MAGMA_BUG%` condition, bug IDs,
   `MAGMA_ENABLE_*` fix macros, comments, and any outcome-revealing names are removed from
   reviewer packets. The safe/vuln label comes only from which variant was compiled,
   tracked in metadata.
7. **Oracle-confirmed outcomes**: vulnerable and fixed outcomes are confirmed by Magma's
   executable oracle (the canary fires on the vulnerable build, not on the fixed build).
8. **Obligation clustering**: usable cases are clustered by the actual **source-to-capacity
   proof obligation**, not by different-looking canary expressions (two canaries with
   different syntax but the same obligation are one family; one canary syntax covering two
   obligations is two).

## Staged feasibility manifest (built BEFORE counting yields)

One row per bug, advancing through explicit stages so gains/losses are visible and no
successful-only subset is selected:

`catalogued → property_candidate → source_available → write_mapped → pair_available →
 scanner_recognized → packet_valid → eligible`

Early stages (`catalogued … pair_available`) are determinable mechanically from the
patches now; the later stages (`scanner_recognized`, `packet_valid`, `eligible`) are
gated on the build-driven scanning integration (`MAGMA_FEASIBILITY.md`) and are marked
`pending_build_integration` until real bodies parse — with a definite negative recorded
where already known (e.g. a canary with no destination write, or a write the scanner
cannot yet recognize). Artifact: `study/magma/feasibility_manifest.{json,csv}`.

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
