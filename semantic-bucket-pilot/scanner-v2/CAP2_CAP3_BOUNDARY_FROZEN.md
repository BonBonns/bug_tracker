# Capability 2 / Capability 3 boundary (FROZEN)

Frozen before capability 3 begins. Both capabilities can encounter pointer-increment
loops; this document fixes which one owns a given write and guarantees one underlying
write is never counted as two experimental operations.

## Definitions

- **Capability 2 — call-site callee write-effect summary (interprocedural).**
  Summarizes a CALLEE's write effect and attributes it AT THE CALL SITE. The physical write
  instruction lives inside the callee body. Two models, both cap2:
  - delegation wrapper (`cap_wrapper_summary.py`) — callee delegates to a library sink;
  - counted-writer/loop (`cap_counted_loop_writer.py`) — callee writes through an
    incremented pointer under a counter.
  Every cap2 record carries `attribution = "call_site_summary"` and
  `underlying_write = {file, line, dest_param}` naming the callee's PHYSICAL write site.

- **Capability 3 — direct pointer-walk writes (intraprocedural).**
  Recognizes pointer-walk writes (`*p++ = ...`) DIRECTLY WITHIN the analyzed function; its
  record is AT the physical write site (`attribution = "direct"`). The write-site
  identification primitive is `cap_write_site_dedup.direct_walk_write_sites`
  (identification only; capacity routing is capability 3 proper, implemented next).

## Robust physical-write identity (frozen)

`(basename(file), line)` is NOT used as identity — it collapses same-named files in
different directories, and it collapses multiple writes on one line. The identity
(`cap_write_site_dedup.physical_write_identity`, used by BOTH cap2 and cap3 so the same
instruction yields the same identity) is:

- **normalized repository-relative file path** — the full path (`dirA/w.c`), not the
  basename; c2cpg records file paths relative to the scan root and preserves subdirectories;
- **enclosing function identity + source span** — `(name, line, line_end)`;
- **line + SITE position** — `("col", N)`, the SOURCE COLUMN of the write on its line,
  read from the source text (`metadata.root` + file). This schema exposes no column field,
  so the column is recovered from source; it is NOT derived from fact-list appearance order
  or node ids. When two writes on one line are otherwise identical, their differing source
  columns keep them distinct. (If the source is unavailable, a flagged `("rank", N)`
  appearance fallback is used; the frozen scans always have source, so `col` is used.)
- **normalized write statement + operator** — `(call name, normalized target code)`;
- **destination DECLARATION identity — built in TWO SEPARATE STEPS:**
  1. **RESOLVE** the write target to its declaration NODE via Joern's reference-target edge
     (`identifiers[].ref_target_ids`, reached by descending the write's argument tree to its
     identifier). This is a semantic reference resolution, NOT a name or
     nearest-declaration heuristic, so it binds correctly across nested scopes — an outer
     `x` used after an inner shadow's block ends resolves to the OUTER declaration.
  2. **SERIALIZE** the resolved declaration node into a stable identity: a parameter is
     `("param", file, function, decl_line, norm_type, index)`; a local is
     `("local", file, function, decl_line, norm_decl_text, decl_ordinal)`, where
     `decl_ordinal` (a source-column rank via the declaration's initializer) only
     disambiguates same-name same-line declarations — it does NOT decide which declaration
     the identifier means (step 1 did). Both cap2 and cap3 resolve+serialize the SAME
     physical write's declaration identically, so their identities agree.

The write-call / node id is retained as WITHIN-RUN provenance only (`node_id` in each
provenance entry); it is NOT part of the cross-run identity, because node ids may change
between runs. The identity does not depend on fact-list appearance order either — all
positional components come from the source text.

**FAIL CLOSED.** If the source text needed to serialize a site column or a same-line
declaration ordinal is unavailable, the identity is marked `verifiable=false`; `dedup`
never merges an unverifiable record (each becomes its own operation flagged
`identity_unverifiable=true`) and trust decisions must exclude them. The unstable
fact-list appearance order is NEVER used as a fallback identity.

## The overlap and the rule (frozen)

When a callee `G` with a pointer-walk loop is in scope and `F` calls `G`, the SAME physical
write is reachable two ways: cap3 recognizes it directly in `G`'s body, and cap2 attributes
`G`'s effect at `F`'s call site. That is ONE underlying write.

- **Deduplicate** by the robust identity key (`cap_write_site_dedup.dedup` /
  `identity_key`).
- **Precedence**: a DIRECT (cap3) recognition is the CANONICAL operation for a physical
  site; a cap2 CALL_SITE_SUMMARY of the same site is a propagated view, retained as
  PROVENANCE, not a second operation. Order: `direct` (0) > `call_site_summary` (1).
- **Both provenance paths are preserved** on the merged operation (`provenance` list),
  including each path's within-run `node_id` and the cap2 `resolved_dest_param`.
- A cap2 call-site summary whose callee body is NOT in scope has no matching direct record
  and stands as one operation; its `underlying_write` still names the site, so a later
  in-scope pass merges it rather than creating a duplicate.

## Controls (frozen, PASS under joern 4.0.608) — `cap_overlap_test.py`

- **(a) different directories**: `cap_controls/idcollide/dirA/w.c` and `.../dirB/w.c` each
  hold a pointer-walk write on the SAME line number; identities differ (full path differs)
  and dedup keeps them SEPARATE — no basename+line collapse.
- **(b) two writes on one line**: `cap_controls/idcollide/sameline/two.c` has two distinct
  `*pa++`/`*pb++` writes on ONE source line; identities differ (ordinal / write text /
  dest_decl) and dedup keeps them SEPARATE.
- **(c) merge**: `cap_controls/overlap/overlap.c` — `f_caller` calls counted-writer
  `g_writer` whose body is in scope. cap2's `underlying_write` and cap3's direct record
  resolve to the SAME identity key; dedup yields exactly ONE operation carrying BOTH
  provenance paths, canonical = the direct recognition.
- **(d) two IDENTICAL writes on one line**: `cap_controls/idadv/adv.c` `twin` has
  `*p++ = v; *p++ = v;` — identical text, operator, dest declaration, file, function, line.
  The two writes get TWO distinct identities (source columns), TWO INDEPENDENT Joern
  rescans produce the SAME two identities, and dedup does not collapse them.
- **(e) shadowed same-line locals**: `cap_controls/idadv/adv.c` `shadow` declares
  `char *x` twice in separate scopes on one line. The two declarations get distinct
  declaration identities (decl ordinal by source column), the two writes are bound by
  reference-target to distinct declarations (ordinals 0/1), and dedup keeps them separate.
- **(f) outer-shadow binding**: `cap_controls/idadv/adv.c` `outer_shadow` — outer `x`
  declared, an inner block shadows `x` and ends, a later write uses the outer `x`.
  Reference-target binds the later write to the OUTER declaration (earliest decl line),
  where a nearest-preceding-name heuristic would mis-bind it to the nearer inner decl; the
  inner write binds to the inner decl, and the two do not merge.
- **(g) fail closed**: with the source root pointed at a nonexistent path, writes become
  `identity_unverifiable`; `dedup` never merges them (each stays a separate flagged
  operation) — appearance order is never used as a fallback identity.

## Consequence for the held-out evaluation

A labeled vulnerable write that lies inside a wrapper/counted-writer callee is counted ONCE
by its physical write site, regardless of how many callers reference it or how many
capabilities recognize it. Recall is measured over physical write sites, not over
(capability × call-site) attributions, so interprocedural propagation cannot inflate the
recognized-site count.

## Boundary for capability 3 work

Capability 3 (pointer-walk writes, intraprocedural, with capacity routing) builds on
`direct_walk_write_sites` and MUST emit `attribution = "direct"` records at physical write
sites, then run through `cap_write_site_dedup.dedup` alongside cap2 records. It must not
modify the cap2 models or move the cap2 gate.
