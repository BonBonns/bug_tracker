# Real-source validation of every corpus reason code

Synthetic gates prove the reason layer is *implemented* consistently. This file
establishes that each reason *means what the taxonomy says* on real disclosed
code: one real record per reason present in the distinct corpus, inspected
against source — including a real cursor abstention and the near-singleton
`unknown_allocator_contract`. Line numbers are the vulnerable/patched revisions
as scanned; source quoted from the cached `csrc/` checkouts.

## required_evidence_absent — insufficient_evidence — additional_evidence_required

- **interproc** `cve-2019-17006 eme_oaep_decode:655` `PORT_Memcpy(output, ...)`.
  `output` is a resolved pointer parameter of `eme_oaep_decode`, but no bounded
  capacity fact propagates to it. Identity is established; capacity evidence is
  absent → `required_evidence_absent`. Not conflicting (no incompatible
  multi-site propagation) and not identity-ambiguous (destination is resolved).
- **cursor** `cve-2019-17006 rsa_FormatOneBlock:132` `*bp++`. `bp` aliases
  `block = PORT_Alloc(modulusLen)`, a symbolic (non-literal) allocation. The
  destination identity is established (single alias) but the capacity is not a
  literal → evidence absent, not ambiguity.

## destination_identity_ambiguous — identity_ambiguous  (real cursor abstention)

- **cursor** `cve-2016-1950 sec_asn1d_concat_group:2329` `*group++ = item->data`.
  `group = sec_asn1d_zalloc(...)` **and** `*placep = group` where
  `placep = (const void***)state->dest`. The cursor write's base identity is
  split between the fresh allocation and the aliased `state->dest` store, so the
  producer cannot resolve a single destination base → `destination_identity_ambiguous`.
  This is exactly "recognized the operation but found multiple/unresolved
  destination bases," distinct from capacity-missing.

## unknown_allocator_contract — external_contract_unknown — semantic_contract_review (llm_eligible)  [near-singleton, 2]

- **runtime** `cve-2016-1950 sec_asn1d_add_to_subitems:1740`
  `copy = sec_asn1d_alloc(state->top->our_pool, len); PORT_Memcpy(copy, data, len);`.
  The destination `copy` comes from `sec_asn1d_alloc`, a project-custom
  pool allocator. Whether it returns ≥ `len` usable bytes depends on that
  allocator's contract, which the scanner does not model → `unknown_allocator_contract`,
  routed to contract review (the task is to establish the allocator's contract
  from its implementation/docs, not to guess) with `llm_eligible: true`. If no
  contract evidence were available the correct degradation is
  `additional_evidence_required` — matching the frozen taxonomy.

## conflicting_reaching_allocations — conflicting_definitions  (the surprising one: emitted by RUNTIME, not interproc)

- **runtime** `cve-2019-11745 NSC_DeriveKey:7664` `PORT_Memcpy(buf, ...)`.
  `NSC_DeriveKey` is a large switch over key-derivation mechanisms; the single
  local `buf` is `PORT_Alloc`'d at a **different size in many mechanism
  cases** (`PORT_Alloc(tmpKeySize)`, and others elsewhere in the function). At
  the write site multiple differently-sized allocation definitions of `buf`
  reach the sink, so no single capacity can be established without collapsing
  the switch-case contexts → `conflicting_reaching_allocations`. This confirms
  the reason is emitted only for genuinely incompatible reaching allocations
  with the binding established — NOT for an unresolved target or missing
  binding — and that the runtime producer (not only interproc) can legitimately
  detect it via reaching-definition analysis.

## capacity_relation_not_established — relationship_unresolved — semantic_relationship_review (llm_eligible, open_candidate)

- **interproc** `cve-2019-11745 nsc_pbe_key_gen:3949` write into `buf`.
  `buf` is a bare `void *buf` **parameter** of `nsc_pbe_key_gen`. Interproc
  propagated a capacity fact to it across a single call hop (identity + capacity
  established), but the write length's relationship to that capacity is not
  proven → `open_candidate` / `capacity_relation_not_established`. This is one
  of the 4 cross-producer conflicts: runtime abstains `required_evidence_absent`
  (no local capacity), interproc reaches `open_candidate` (propagated capacity);
  the evidence-monotone dedup keeps interproc's more-informed verdict as
  canonical.

## write_count_bound_not_established — relationship_unresolved — semantic_relationship_review (open_candidate)

- **cursor** `mjpg-cve-huff encode_one_block:517` cursor writes into local
  `buffer` through the Huffman `PUT_BITS`/emit machinery. The number of bytes
  written is not provably ≤ the buffer's capacity → `open_candidate` /
  `write_count_bound_not_established`. This is the mozjpeg CVE shape; the scanner
  flags the count-vs-capacity relationship identically in the vulnerable and
  patched revisions (only the `BUFSIZE` constant differs, which the scanner
  correctly does not itself adjudicate).

## Summary

All six reason codes present in the distinct corpus are backed by ≥1 real,
source-inspected instance whose meaning matches the taxonomy; the requirement
of a real cursor abstention and inspection of the near-singleton reason are
met. `deterministic_complete` (2 records) is a proven-safe state, not a reason
code, and carries no bucket.
