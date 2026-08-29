# Held-out failure diagnosis (analysis only — no scanner changes)

Post-hoc diagnosis of why the frozen scanner reached only 7 of 194 mapped labeled writes across
the two held-out runs (175 vulnerable + 101 non-vulnerable SecVulEval function packets = 276
built bodies). **Analysis only: no capability/producer/normalizer/exporter changed.** Every fact
below is derived from a deterministic re-scan whose `cpp.json` is cached under
`cache/` (`raw_diagnosis.jsonl`), so no further re-scan is ever needed.

**Corpus status:** this post-hoc analysis does NOT invalidate the already-archived confirmatory
result, but the 258-site vulnerable corpus is **consumed** and cannot serve as held-out
confirmation for a *modified* scanner. A new, unseen corpus is required for any future
confirmatory generalization claim.

## Harness-bug check (found and fixed during diagnosis; ZERO effect on the result)

`analyze_counted_writers()` returns a tuple `(ops, summaries)`; the eval harness iterated it
inside a `try/except`, so **cap2 counted-loop-writer was silently disabled** in the archived run.
The scanner (`cap_counted_loop_writer.py`) is byte-identical to frozen `544a606`; only the harness
mis-called it. Impact, measured across all 276 bodies with the fixed code: **cap2 counted-loop
fires at 0 labeled writes.** The 7 recognized sites are all via runtime_capacity / cursor /
interprocedural — exactly the archived count. **The archived 4/118 (vuln) and 7/194 (combined)
STAND**; the bug was a latent defect with no outcome impact. Harness fixed regardless.

## Step 0 — label validity (the labels are noisy)

Of 276 labeled "write" sites: **212 destination_write, 62 pointer/variable declaration, 1
comment, 1 guard** → **64 (23 %) are NOT destination writes.** SecVulEval's write-site labeling
flags declaration lines (e.g. `struct pfkey_sock *pfk = pfkey_sk(sk);`) and the occasional
comment/guard as the "write." Only confirmed destination writes belong in a scanner-recognition
denominator. All 7 recognized sites are genuine destination_writes.

## Step 1 — CPG absence for confirmed writes (incomplete function-packet parsing)

Of the 82 unmapped sites, **69 are confirmed destination writes** absent from the CPG (13 are
declarations/comments — label noise, not scanner failure). The 69 split:

- **61 / 69 (88 %) = whole-packet parse failure** (`empty_or_degenerate_cpg`, <10 nodes): the
  function packet barely parsed at all. Cause is missing declarations / unresolved macros &
  attributes in the *signature or types* (e.g. `const char __user *`, `enum` params) that make
  c2cpg abandon the function.
- **8 / 69 = partial-region drop**: most of the body parsed but the labeled statement's block did
  not, from an undefined macro/constant in the body (e.g. the `NFS4_MAXLABELLEN`-guarded block
  around a `memcpy`).

This is **not** line reconstruction (zero text-match failures) and **not** target matching. It is
incomplete parsing of extracted function packets — overwhelmingly whole-function collapse.

## Step 2 — producer rejection of mapped confirmed writes (actual gates, not shape-inferred)

143 mapped confirmed writes → 7 recognized, **136 rejected**. The gate is the producers' own
decision (each producer run on the cached `cpp.json`; the failing precondition read from the
producers' own extent functions):

- **89 / 136 = `write_form_not_in_any_producer_domain`** — the write form is outside every
  modeled shape. By kind: **pointer_deref 69, index_write 20**. These are general indexed / member
  / pointer writes that are not the modeled `&a[i]` (cap1), byte `*p++` cursor, advancing-pointer
  member walk (cap3), copy-sink, or decoder call.
- **39 / 136 = `destination_capacity_not_established`** — a producer *recognized* the write shape
  (memcpy-family etc.) but the destination has no independently-established byte extent. Decl kind
  of the dest: **local 18, struct_field 11, parameter 7, unresolved 3** (a `memcpy` into a local
  with no fixed-array/alloc extent in the packet, or into a struct field / caller-supplied param).
- **8 / 136 = capacity established but the relation was not promoted** (open-candidate residue).

## Step 3 — the 7 recognized writes all abstain (`required_evidence_absent`)

| site | v | producer(s) | dest decl | extent bound |
|---|:-:|---|---|---|
| evutil_parse_sockaddr_port | 1 | runtime_capacity | local | stack_fixed_array |
| msg_parse_fetch | 1 | cursor | local | none |
| blosc_c | 1 | interproc + runtime_capacity | parameter | none |
| enc_untrusted_recvfrom | 1 | interproc + runtime_capacity | parameter | none |
| nsc_rle_decode | 0 | interproc + runtime_capacity | parameter | none |
| msg_parse_fetch | 0 | cursor | local | none |
| new_creator | 0 | runtime_capacity | local | none |

Only one (`evutil_parse_sockaddr_port`) bound a destination extent at all (a stack fixed array),
and it still abstained (the length/relation, not the capacity, was unestablished). The other six
have no bindable extent (caller-supplied parameter or an unbounded local). None reached a verdict.

## Step 4 — cross-tab (label_class × funnel stage, 276 built)

| label_class | unmapped | mapped-rejected | recognized |
|---|--:|--:|--:|
| destination_write | 69 | 136 | 7 |
| pointer_or_var_declaration | 12 | 50 | 0 |
| comment_or_nonstatement | 1 | 0 | 0 |
| guard_or_control | 0 | 1 | 0 |

50 declarations that *mapped* were correctly not recognized (they are not writes) — these inflate
the raw "mapped rejected" count and are removed by the validated-write denominator.

## Step 5 — label-validity sensitivity (frozen primary PRESERVED)

- **PRIMARY (frozen, unchanged): vuln conditional recall = 4 / 118 = 3.39 %.**
- Label-validity sensitivity (recognized / mapped **destination_writes** only): **4 / 84 = 4.76 %**
  (vuln); **7 / 143 = 4.90 %** (combined). This is reported *alongside*, not as a replacement.

## Conclusion — three separate defects, quantified

Low coverage is NOT primarily an adjudication problem. **Adjudication accuracy was not exercised
at all** — the scanner emitted **zero deterministic vulnerability/safety verdicts** on held-out
code, so there were zero opportunities for an adjudication error. Zero opportunities is NOT
evidence of zero adjudication errors. The pipeline almost never delivers a complete operation to
adjudication, for three distinct reasons (see TRACE54.md for the site-level seven-field trace of
the 54 producer-reaching cases):

1. **Noisy target labels** — 64/276 (23 %) labeled sites are not destination writes (declarations,
   comment, guard).
2. **Incomplete function-packet parsing** — 69 confirmed writes never reach the CPG, 88 % of them
   from whole-function parse collapse on missing declarations / macros / attributes.
3. **Genuinely unsupported representations & unbindable capacity** — of 143 mapped confirmed
   writes, 89 are write forms outside every modeled shape and 39 recognize the shape but cannot
   bind a destination extent from the function packet; only 7 reach evidence binding, where all 7
   abstain for lack of capacity/length evidence.

Any fix (broader modeled forms, full-repository builds to supply declarations/macros, or
label-validity filtering) would be scanner/harness development motivated by these misses, which
turns this corpus into development data. A new held-out corpus is required for the next
confirmatory claim.
