# Capability-3 domain-overlap audit vs the frozen cursor producer (FROZEN)

Run before implementing capability 3, to guarantee capability 3 does not rediscover and
double-count writes the frozen `oob_cursor_write_verdict` producer already models. Machine
artifact: `study/magma/CAP3_DOMAIN_AUDIT.json`; re-runnable gate: `cap3_domain_audit.py`
(`CAP3_DOMAIN_AUDIT=PASS`). Frontend joern-c2cpg v4.0.608. No model calls.

## Method

Both the FROZEN cursor producer (`oob_cursor_write_verdict.analyze_operations`) and the
`cap_write_site_dedup.direct_walk_write_sites` primitive are run on six representation
shapes; every physical write site is classified by robust physical-write identity into
cursor / direct / overlap. A member-through-advancing-pointer probe characterizes the
uncovered shape (the capability-3 target).

## Results (per fixture)

| fixture | shape | cursor | direct `*p++` | overlap | member-walk (cap3) |
|---|---|---:|---:|---:|---:|
| a1_raw_deref | `*p++` byte buffer | 1 | 1 | 1 | 0 |
| a2_offset_deref | `*(p+n)`, advancing p | 1 | 0 | 0 | 0 |
| a3_struct_member | `pp->field=…; pp++` | 0 | 0 | 0 | 3 |
| a4_array_backed | `*p++` fixed array | 1 | 1 | 1 | 0 |
| a5_heap_backed | `*p++` malloc(literal) | 1 | 1 | 1 | 0 |
| a6_png003 | PNG003 palette walk (real) | 0 | 0 | 0 | 3 |

## Frozen domains

- **existing_cursor_domain** — pointer-DEREFERENCE writes on byte buffers with a resolvable
  capacity: `*p = x`, `*p++ = x`, `*(p+n) = x` (regexes `INCR_WRITE_RE` / `DEREF_WRITE_RE`
  / `OFFSET_DEREF_WRITE_RE`; base identity chained through `p=arr` and `q=p`; static byte
  arrays and literal-constant `malloc`/`PORT_Alloc`). Does NOT model member writes
  (`p->field`), non-byte aggregate elements, or call-argument sinks. Fixtures a1, a2, a4, a5.

- **new_capability_3_domain** — pointer-walk writes the cursor producer MISSES: a write
  through an ADVANCING pointer whose target is a STRUCT/UNION MEMBER (`base->field` /
  `base.field`) and/or whose element is a non-byte aggregate (e.g. `png_color[]`). The
  canonical case is PNG003 `png_handle_PLTE` (`pal_ptr->red/green/blue = buf[..]`,
  `pal_ptr++`) — `scanner_ok=false` in the frozen Magma screen. Fixtures a3, a6 (3 member
  writes each). This is what capability 3 will implement.

- **overlap_domain** — raw / array-backed / heap-backed `*p++` on byte buffers, recognized
  by BOTH. Fixtures a1, a4, a5.

## Dedup / precedence rule (frozen)

Deduplicate by robust physical-write identity (`cap_write_site_dedup`). PRECEDENCE
`cursor_producer > direct (cap3) > call_site_summary (cap2)`. For a site in the overlap
domain the FROZEN cursor producer is CANONICAL; capability 3 enriches its evidence or
abstains and is retained only as PROVENANCE — it NEVER emits a second operation. Both
producer provenances are preserved on the merged operation. Verified: on a1/a4/a5 the
cursor and direct records merge to ONE operation with `canonical_attribution =
cursor_producer` and provenances `[cursor_producer, direct]`. Capability 3 OWNS only the
new_capability_3_domain sites, where the cursor recognizes nothing.

## Consequence for capability 3

Capability 3 is implemented specifically for the new_capability_3_domain (member /
non-byte-element pointer walks). Its records enter the same `dedup`; on any site the
frozen cursor already recognizes, the precedence rule keeps the cursor canonical and
capability 3 does not double-count.
