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

**Important asymmetry, stated plainly:** the *consumption* side (the
normalizer's fail-closed check, given `aggregate_kinds.tsv` says UNION) is
fully tested above. The *production* side (the `.sc` script's guess that a
union's `TypeDecl.code` literally starts with the text `"union"`) is
**unverified** -- there is no Joern install in this environment to confirm
that's actually how c2cpg represents a union's `code` field. Said directly
in the `.sc` file's own comment: treat every `UNION` classification it would
produce as a hypothesis until checked against a real CPG, not as validated
behavior. If it guesses wrong in either direction, the *safe* failure mode
holds either way: guessing "not a union" when it is one reproduces exactly
today's pre-fail-closed behavior (a real gap, but not a new one this session
introduced); guessing "union" when it isn't one only costs a missed
candidate, never a false capacity claim.

## Remaining, explicitly open (unchanged from round 1 unless noted)

- Casts and shadowed declarations on the struct-member path -- still not
  exercised by a fixture.
- The `.sc` script's union-detection heuristic -- unverified, as above.
- Full-repository parsing with real headers/macros, running the ~40
  unrelated gates elsewhere in the tree, and a new held-out corpus --
  still out of scope for this gate, as in round 1.

## Scope and limitations -- explicitly NOT done this session

Reporting these as open rather than silently dropping them, per this
project's own abstain-by-default convention:

- **No real Joern run.** Joern is not installed in this environment (`which
  joern*` finds nothing). Every fixture here is a hand-built raw-TSV stand-in
  for what `export_c_cpp_facts_v03.sc` would emit for the given C shape,
  following the exact convention already used by this test suite's other
  `make_*_raw.py` fixtures (e.g. `cpp-r06/tests/make_memory_r02_raw.py`).
  This is real, executed evidence of the *normalizer's* behavior on that
  input -- it is not evidence of what Joern's c2cpg would actually produce
  from real NSS source, most importantly whether `typeFullName` really does
  carry `MAX_KEY_LEN` already expanded to `256` (this repo's own prior
  finding, in `moz-scan-paired-cve-validation-round1.md`, that a real
  scan of `mozjpeg/jchuff.c`'s `BUFSIZE` macro arrived pre-expanded as
  `(64*2)+8` supports that assumption, but it is an assumption carried over
  from a different corpus, not verified fresh against NSS specifically).
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
