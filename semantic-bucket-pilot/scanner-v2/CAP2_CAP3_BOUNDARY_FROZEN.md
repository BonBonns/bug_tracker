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

## The overlap and the rule (frozen)

When a callee `G` with a pointer-walk loop is in scope and `F` calls `G`, the SAME physical
write (`G:line`) is reachable two ways: cap3 recognizes it directly in `G`'s body, and cap2
attributes `G`'s effect at `F`'s call site. That is ONE underlying write.

- **Write-site identity** = `(basename(file), line)` of the physical write instruction. For
  a cap2 record it is its `underlying_write`; for a cap3 record it is the record's own site.
- **Deduplicate** by write-site identity (`cap_write_site_dedup.dedup`).
- **Precedence**: a DIRECT (cap3) recognition is the CANONICAL operation for a physical
  site; a cap2 CALL_SITE_SUMMARY of the same site is a propagated view, retained as
  PROVENANCE, not a second operation. Precedence order: `direct` (0) > `call_site_summary` (1).
- **Both provenance paths are preserved** on the merged operation (`provenance` list), so
  the interprocedural path is not lost — it is just not double-counted.
- A cap2 call-site summary whose callee body is NOT in scope has no matching direct record
  and stands as one operation; its `underlying_write` still names the site, so a later
  in-scope pass merges it rather than creating a duplicate.

## Control (frozen, PASS under joern 4.0.608)

`cap_controls/overlap/overlap.c`: `f_caller` calls the counted-writer `g_writer`, whose body
(one physical `*u++ = ...` write) is in scope. `cap_overlap_test.py` asserts:
- cap2 emits one call-site summary in `f_caller` with `underlying_write` into `g_writer`;
- the cap3 primitive finds exactly one direct write in `g_writer`;
- both resolve to the SAME write-site key;
- after `dedup`, there is exactly ONE merged operation for that site (not two), carrying
  BOTH provenance paths, with the DIRECT recognition canonical.

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
