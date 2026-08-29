# NSS-SSLMAC-CAPACITY-R01: struct-member fixed-array capacity model

Development regression for the general struct-member capacity model,
seeded directly from the ASan-confirmed real bug in
`lib/softoken/pkcs11c.c`'s `sftk_doSSLMACInit()` (NSS upstream commit
`7b5f00bfd3835fee76be428c55e60cdb3366182c`):

```c
struct SFTKSSLMACInfoStr {
    ...
    unsigned char key[MAX_KEY_LEN];   // MAX_KEY_LEN == 256, pkcs11i.h:74
    unsigned int keySize;
};
...
sslmacinfo = (SFTKSSLMACInfo *)PORT_Alloc(sizeof(SFTKSSLMACInfo));
...
PORT_Memcpy(sslmacinfo->key, keyval->attrib.pValue,
            keyval->attrib.ulValueLen);          // no bound check anywhere
```

Reproduced dynamically this session (ASan heap-buffer-overflow, escalating
to SEGV) via `C_SignInit`/`CKM_SSL3_MD5_MAC`; see the conversation's earlier
`mac_init_test2.c` / `mac_init_test2_asan.log` for that evidence. This gate
is the *static* counterpart: does the scanner's fact pipeline model this
shape at all, and if so, does it correctly report it as an open bound
obligation rather than either fabricating a bound or silently abstaining?

## What this gate found and fixed

Two real gaps in `frontend/normalize_c_cpp_facts_v03.py`, found by building
this exact shape as a hand-crafted raw-fact fixture (no Joern available in
this environment -- see Scope/limitations) and running it through the real
normalizer, not by inspection alone:

1. **`PORT_Memcpy`/`PORT_Memmove` were absent from `_OPERAND_ROLES`.**
   The existing table only knew plain libc `memcpy`/`memmove`/etc. NSS's
   own copy wrapper -- the actual callee at the real bug site -- was
   invisible to the entire downstream operand-role / capacity / bound
   pipeline. Without this fix, the pipeline abstains on the confirmed real
   bug with zero facts emitted, indistinguishable from "nothing to see
   here." Added `PORT_Memcpy`, `PORT_Memmove`, `wmemcpy`. Verified as
   load-bearing by a negative control (same fixture, unregistered callee
   name -> zero facts).

2. **`_fixed_array_capacity` only accepted a bare integer array dimension.**
   A macro used as a dimension survives into `typeFullName` as whatever the
   preprocessor left there: a bare literal for a plain `#define NAME 256`
   (NSS's `MAX_KEY_LEN` -- already worked, since 256 is itself a bare
   digit), or a constant *arithmetic expression* for an arithmetic macro
   (mozjpeg's `#define BUFSIZE (DCTSIZE2*2)+8` -- did NOT work; this is
   already handled for *local* arrays by
   `tools/oob_copy_length_verdict.py`'s `_eval_const_int_expr`, but was
   never wired into the *struct-member* capacity path). Generalized the
   regex and added the identical restricted-eval folding (digits/whitespace
   `+-*/()` only, checked before `eval` ever runs) so struct members get the
   same treatment local arrays already had.

Both fixes are additive/widening only (verified no regression: the existing
`CPP_MEMORY_R02` Java e2e suite, 15/15, and the `CPP_DYNAMIC_NO_HARDEN`
check both still pass unchanged against the patched normalizer).

## Result on the confirmed real site (`raw_nss_site/`)

```json
{"dest_capacities": [{
  "capacity_bytes": 256, "elem_type": "unsigned char", "elem_count": 256,
  "resolution": "EXACT_STORAGE_IDENTITY", "storage_identity_kind": "FIELD",
  "field_storage_key": "FIELD:10:100",
  "derivation": {"rule": "CPP_STRUCT_MEMBER_ARRAY_CAPACITY"}
}]}
```
```json
{"bounds": []}
```

Exactly the proof obligation asked for:
- **Destination:** `sslmacinfo->key`
- **Declaration:** `key[MAX_KEY_LEN]`
- **Capacity:** 256 bytes (`CPP_STRUCT_MEMBER_ARRAY_CAPACITY`, `EXACT_STORAGE_IDENTITY`)
- **Write extent:** `keyval->attrib.ulValueLen` (the memcpy's `EXTENT` operand)
- **Guard:** `.bound.json` is empty -- no comparison anywhere relates the
  extent to this capacity
- **Result:** `open_candidate` / `relationship_unresolved`, naming the
  missing upper bound as **256 bytes**

## Adversarial matrix (`build_and_check.py`, 24/24 passing)

| Scenario | Expected | Result |
|---|---|---|
| Real NSS site (`unsigned char key[256]`, `PORT_Memcpy`) | capacity=256, no bound | PASS |
| Negative control (unregistered callee name) | zero facts (abstain) | PASS |
| Pointer member (`unsigned char *key`) | no capacity fabricated; `POINTER_MEMBER` | PASS |
| Flexible array member (`unsigned char key[]`) | no capacity fabricated; `UNKNOWN_ARRAY_DIMENSION` | PASS |
| Arithmetic-macro dimension (`unsigned char buf[(64*2)+8]`) | capacity=136, resolved by the folding fix | PASS |
| Member name ambiguous across two structs with *different* array sizes (`StructA.buf[16]` vs `StructB.buf[512]`) | resolves via base-identifier's own type (16), never conflates with 512 | PASS |
| Offset shape `obj->key + off` | capacity=256, `offset_shape=True`, `offset_expr="off"`, still no bound fact | PASS |
| Offset shape `&obj->key[off]` | capacity=256, `offset_shape=True`, `offset_expr="off"` | PASS |
| Bare field access (no offset) | `offset_shape` explicitly `False`, not just absent | PASS |
| Union member (`UnionKeyInfo.key[256]` flagged via `aggregate_kinds.tsv`) | no capacity fabricated; `UNION_MEMBER_FAIL_CLOSED` | PASS |
| Union member reached via an offset shape (`u.key + off`) | still no capacity fabricated (fail-closed holds through both paths) | PASS |

Run: `python3 build_and_check.py` from this directory (pure Python, no
Joern/Java needed for this part -- only the CPP_MEMORY_R02 cross-check
above needs `javac`/`java`, both present in this environment and confirmed
passing).

## Round 2: struct-member offsets + fail-closed unions

Two more real gaps found and fixed, same session, same "abstain rather than
guess" posture:

1. **`p->buffer + n` and `&p->buffer[n]` as a copy destination were
   completely invisible.** `memory_targets()`/`value_ref()` only resolve a
   bare field access; an offset on top of one falls through to
   `{'kind':'CALL', ...}`, which the destcapacity code had no handler for --
   so the write silently produced *zero* facts, not a flagged-but-uncertain
   one. Added `_offset_field_capacity()`, wired as a fallback in the same
   operand-role loop, recognizing exactly `<operator>.addition(fieldAccess,
   offset)` and `<operator>.addressOf(indexAccess(fieldAccess, offset))`.
   Matches `oob_copy_length_verdict.py`'s existing posture for *local*
   arrays: emits the member's **full** declared capacity tagged
   `offset_shape: true, offset_expr: "<the offset text>"` -- an open
   candidate, never a computed "capacity minus offset" bound (offset may be
   an arbitrary runtime expression). `.bound.json` is deliberately never
   populated for an offset shape either, for the same reason.

2. **Union members had no fail-closed handling because the raw fact schema
   had no way to say "this is a union" at all.** `export_c_cpp_facts_v03.sc`
   never exported an aggregate kind (struct vs union vs class), and no
   consumer checked for one. Added a new, fully **optional** raw fact,
   `aggregate_kinds.tsv` (`type_decl_id -> 'UNION'|'STRUCT'|'CLASS'`) --
   absent from every pre-existing fixture and therefore behaviorally a
   no-op for all of them (verified: `CPP_MEMORY_R02` 15/15 and
   `CPP_DYNAMIC_NO_HARDEN` still pass unchanged). When a member's owning
   `type_decl_id` is flagged `UNION`, capacity resolution now unconditionally
   abstains for that member -- through *both* the bare-field-access path and
   the new offset-shape path -- tracked as `UNION_MEMBER_FAIL_CLOSED`.
   Fail-closed here means: never claim a capacity for a union member, even
   though a union member's own declared array size is technically real
   backing-store capacity for an isolated write -- this scanner makes no
   claim about which member is the currently-live one, and a bare capacity
   fact could be read as implying more than that.

**Important asymmetry, stated plainly (round 2; resolved in round 3 below):**
the *consumption* side (the normalizer's fail-closed check, given
`aggregate_kinds.tsv` says UNION) was fully tested above. The *production*
side (the `.sc` script's guess that a union's `TypeDecl.code` literally
starts with the text `"union"`) was **unverified** -- there was no Joern
install in the environment round 2 was written in to confirm that's
actually how c2cpg represents a union's `code` field.

## Round 3: real Joern validation of the `.sc` producer (Joern v4.0.608)

Round 2 flagged the `.sc` script's `TypeDecl.code`-prefix heuristic as an
unverified hypothesis. This round installs the pinned Joern (`v4.0.608`,
per `tchecker-research-complete/bootstrap.sh`), builds a real CPG from a
hand-written fixture exercising every aggregate shape the task asked for
(named struct/union/class, `typedef` aliases of the struct and union,
anonymous struct/union, bare member expressions, `obj->buffer + off`, and
`&obj->buffer[off]`), runs the real `export_c_cpp_facts_v03.sc` against it,
and traces IDs through `type_decls.tsv` -> `aggregate_kinds.tsv` ->
`members.tsv` -> `calls.tsv` -> `arguments.tsv` into the normalizer's
output.

**The heuristic was correct for every shape except one, and that one
divergence was a real, silent, security-relevant bug -- not merely an
"unverified but harmless" gap.**

Confirmed `TypeDecl.code` for each shape (real Joern output, not inferred):

| Shape | `TypeDecl.code` | Prefix match |
|---|---|---|
| `struct NamedStruct { unsigned char buffer[256]; };` | `"struct NamedStruct {\n    unsigned char buffer[256];\n}"` | matches `"struct"` |
| `union NamedUnion { unsigned char buffer[256]; ... };` | `"union NamedUnion {\n    unsigned char buffer[256];\n...}"` | matches `"union"` |
| `class NamedClass { public: unsigned char buffer[256]; };` | `"class NamedClass {\npublic:\n    unsigned char buffer[256];\n}"` | matches `"class"` |
| anonymous `struct { unsigned char buffer[256]; } anonStructInstance;` | `"struct {\n    unsigned char buffer[256];\n}"` | matches `"struct"` |
| anonymous `union { unsigned char buffer[256]; } anonUnionInstance;` | `"union {\n    unsigned char buffer[256];\n}"` | matches `"union"` |
| `typedef struct NamedStruct StructAlias;` | `"typedef struct NamedStruct StructAlias;"` | **matches nothing** (starts with `"typedef"`) |
| `typedef union NamedUnion UnionAlias;` | `"typedef union NamedUnion UnionAlias;"` | **matches nothing** (starts with `"typedef"`) |

So a typedef'd alias's own `TypeDecl` was always left `UNKNOWN` by the
pre-round-3 heuristic. On its own that would just be a missed candidate --
consistent with the stated "fails safe" design. It is not safe, and here is
the join trace that proves it:

`members.tsv` is built by `cpg.typeDecl.l.foreach { t => t.member.l... }` --
one row **per (owning TypeDecl, member) pair**. c2cpg re-exposes the SAME
member node id under BOTH the real union's TypeDecl and the alias's
TypeDecl (confirmed: member id `98784247809` ("buffer") appears in
`members.tsv` with `type_decl_id=<NamedUnion>` AND, later in the same file,
with `type_decl_id=<UnionAlias>`). The normalizer indexes members by id
with `_memdecl_by_id={_md['id']:_md for _md in members}` -- a plain dict
comprehension, so the LAST row for a given member id wins. Because
`cpg.typeDecl.l` yields TypeDecls in roughly source order and the typedef
is declared after the struct/union it aliases, the alias's (misclassified,
`UNKNOWN`) row silently overwrote the real union's (correctly `UNION`)
row for that shared member id.

**Consequence, reproduced end-to-end against real Joern output before any
fix (`raw_real_joern_aggkinds/`, `fixture_source.cpp`):** a plain
`memcpy(u->buffer, src, n)` where `u` is `NamedUnion*` -- accessing the
union directly, never through the alias, in a function that never even
mentions `UnionAlias` -- fabricated a real capacity fact
(`CPP_STRUCT_MEMBER_ARRAY_CAPACITY`, `capacity_bytes: 256`) purely because
a `typedef union NamedUnion UnionAlias;` existed **anywhere else in the
same translation unit**. The same held for the offset-shape path
(`&u->buffer[off]`) and for access through the alias itself. This is
exactly the false-capacity-claim-on-a-union outcome round 2's fail-closed
design exists to prevent, defeated by an unrelated declaration elsewhere
in the file.

**Fix applied (`export_c_cpp_facts_v03.sc`):** resolve a typedef through
`TypeDecl.aliasTypeFullName` -- a real, stable semantic property Joern
populates for every typedef (confirmed: `StructAlias.aliasTypeFullName ==
"NamedStruct"`, `UnionAlias.aliasTypeFullName == "NamedUnion"`), not a text
guess -- to the aliased type's own `TypeDecl` and classify from *that*
`TypeDecl`'s code instead of the alias's own `"typedef ..."` text. Bounded
(8 hops), cycle-safe, for chained typedefs; only ever resolves through a
LOCAL (non-external) same-named definition, and leaves an alias `UNKNOWN`
rather than guessing between multiple same-named candidates. Strictly
additive over the round-2 heuristic: only ever turns an `UNKNOWN` into a
real kind, never changes a kind the code-prefix check already resolved --
so every round-1/round-2 fixture (which never has a typedef in its
hand-built raw facts) is provably unaffected.

**Verified fixed, same real CPG, same fixture, exact tracked `.sc` file
(`raw_real_joern_aggkinds/aggregate_kinds.tsv`):** `StructAlias` now
classifies `STRUCT`, `UnionAlias` now classifies `UNION`. Re-running the
same `memcpy(u->buffer, ...)`, `memcpy(&u->buffer[off], ...)`, and
`memcpy(ua->buffer, ...)` call sites through the real, unmodified
normalizer now produces **zero** dest-capacity facts for all three
(`UNION_MEMBER_FAIL_CLOSED`), while the struct/class equivalents
(`copyStructBare`, `copyStructOffset` (`+off`), `copyStructIndexOffset`
(`&x[off]`), `copyClassBare`, `copyViaStructAlias`) all correctly resolve
to `capacity_bytes: 256`, with `offset_shape`/`offset_expr` retained
verbatim on the two offset-shaped facts and no `BoundFact` ever produced
for either. See `check_real_joern_aggkinds.py` (24/24) for the executable
form of every claim in this section, and `raw_real_joern_aggkinds/` for the
frozen real Joern output it runs against (regeneration command in that
script's docstring; Joern is not required to re-run the check itself,
only to regenerate the frozen raw facts from a changed fixture).

No change was needed to `normalize_c_cpp_facts_v03.py` -- the consumption
side was already correct once given a correct `aggregate_kinds.tsv`;
round 2's own claim that the consumer was "fully tested" holds up
unchanged against real output.

Regression, same real CPG pipeline (`c2cpg.sh` + this `.sc` file +
`joern`), Joern v4.0.608:
- `CPP_R06` (`tests/gates/cpp-r06/run.sh`, real Joern, unrelated to member
  capacity -- basic call-graph loader sanity): 10/10, unchanged.
- `CPP_MEMORY_R02`: 15/15, unchanged (hand-built raw facts, never touches
  the `.sc` file).
- `CPP_DYNAMIC_NO_HARDEN`: 1/1, unchanged (same reason).
- This gate's own 24/24 (`build_and_check.py`): 24/24, unchanged (same
  reason -- none of those fixtures build a typedef).

## Remaining, explicitly open

- Casts and shadowed declarations on the struct-member path -- still not
  exercised by a fixture.
- Multi-level typedef chains (`typedef UnionAlias UnionAlias2;`) and a
  same-named type redefined ambiguously across translation units -- the
  round-3 fix handles chains up to 8 hops and deliberately abstains
  (leaves `UNKNOWN`) rather than guessing when a name resolves to more
  than one local `TypeDecl`, but neither case has its own fixture yet.
- Full-repository parsing with real headers/macros, running the ~40
  unrelated gates elsewhere in the tree, and a new held-out corpus --
  still out of scope for this gate, as in round 1.

## Scope and limitations -- explicitly NOT done this session

Reporting these as open rather than silently dropping them, per this
project's own abstain-by-default convention:

- **No real Joern run against actual NSS source.** Round 3 (above) did
  install the pinned Joern (`v4.0.608`) and run a real CPG through the real
  `export_c_cpp_facts_v03.sc` and the real normalizer -- so the prior
  "hand-built raw-TSV stand-in, unverified against real output" limitation
  no longer holds for the aggregate-kind producer or for the round-1/round-2
  struct-member-capacity shapes in general. What round 3 did NOT do is
  rescan the actual NSS source tree: the round-3 fixture is a minimal,
  hand-written `.cpp` file covering the aggregate shapes the task asked for
  (named/anonymous struct/union/class, typedef aliases, bare and both
  offset forms), not `lib/softoken/pkcs11c.c` itself. Whether `typeFullName`
  for `SFTKSSLMACInfoStr.key` really does carry `MAX_KEY_LEN` pre-expanded
  to `256` in a real NSS build (this repo's own prior finding, in
  `moz-scan-paired-cve-validation-round1.md`, that a real scan of
  `mozjpeg/jchuff.c`'s `BUFSIZE` macro arrived pre-expanded as `(64*2)+8`
  supports that assumption, but it is carried over from a different
  corpus) remains unverified against NSS specifically.
- **"Rescan real NSS" / "run every frozen capability gate"** -- not done.
  Most of the ~40 gates elsewhere in this tree (malicious-npm, denylist-
  bypass, serialize-DoS, state-provenance, various TypeScript gates, ...)
  are unrelated pipelines addressing unrelated properties; running them
  buys nothing for this specific capability and several need their own
  Joern/JS toolchains not present here either. Not attempted.
- **No new held-out corpus evaluation.** No such corpus exists in this
  environment to evaluate against; building one is a separate, large task
  the original request also flagged as a later step, not this one.
- **Offset handling and union fail-closed handling** -- now implemented,
  see "Round 2" above.
- **Casts and shadowed declarations on the struct-member path** -- not
  exercised by a fixture. The general cast pass-through in `value_ref()`
  covers casts on ordinary values; whether it composes correctly with the
  field-identity/capacity resolution above specifically was not tested.
- **Full-repository parsing with real headers/macros** -- explicitly called
  out in the original request as the *next* major target after this one,
  not part of this gate. Not attempted.
