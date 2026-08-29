# Verification: V1/V2 delegation regression against the real 276-body cache

**Purpose.** `cc643bb` (`claude/emission-gap-delegation`) was NOT considered merge-ready
until its `regression.py` was run against a real 276-packet CPG cache — the sibling session
that authored the branch did not have the (gitignored) cache in its worktree and validated
only via synthetic controls. This run supplies that missing confirmation from a hash-verified
copy of the cache.

**Verification only — no scanner/producer/capability code was modified.** The branch under test
(`cc643bb`) was checked out into an isolated worktree; the frozen confirmatory branch
(`claude/previous-conversation-context-6gr99h`) and `claude/emission-gap-fix` were untouched.

## Provenance

| item | value |
|---|---|
| branch under test | `claude/emission-gap-delegation` @ `cc643bb076b4e648c3ab434c6422dabde8d43d21` |
| built on | `70805e2` (form-aware split) → `23d84cc` (delegation) → `cc643bb` (schema-v2 + v1_provenance) |
| cache | 276 function-packet CPGs, read-only immutable copy |
| cache Merkle (sha256 of sorted `sha256(file)  basename`) | `5d8db6f82b695226021b39dbe1b4befae7ee7e0f92ac728fcc267df1b6a65e02` |
| `raw_diagnosis.jsonl` sha256 | `c987153c2e5cab1a6700e6f82c0542b4a88f59748f03072641df09f77066efcf` (matches archived `.sha256`; worktree copy identical) |
| cache completeness | 276 files ↔ 276 `site_id[:16]`, 0 missing, 0 extra |
| Joern/c2cpg | not re-invoked (cache reused; no re-scan) |

## Result summary — every requested assertion holds

| # | assertion | result |
|---|---|---|
| 1 | 45/45 body-wide non-bare operations still emit (none newly dropped) | **PASS** (45 emit, 0 dropped) |
| 2 | labeled group-A remains exactly 13/20 | **PASS** (10 `required_evidence_absent` + 3 `destination_identity_ambiguous`) |
| 3 | exactly the two expected body-wide dispositions change to the delegation path | **PASS** (exactly 2, both `capacity_relation_not_established` → `delegated_to_stack_capacity_v2` / `rerouted`; other 43 byte-identical) |
| 4 | zero unexpected site additions or losses | **PASS** (baseline `70805e2` and `cc643bb` non-bare site sets identical, 45↔45) |
| 5 | zero unsupported V2 safe/oversized promotions beyond the 2 changed sites justify | **PASS** (see below) |
| 6 | V2 canonical; V1 rerouted handoff retained as `v1_provenance` on every adjudicated record | **PASS** (2/2 delegated carry `v1_provenance`; V2 status ≠ rerouted) |
| 7 | every emitted record validates under `analysis_record.validate_record()` (schema "2") | **PASS** (V1 0 invalid / 64, V2 0 invalid / 64) |
| 8 | archived schema-v1 records still validate; additive-only change | **PASS** (`ANALYSIS_RECORD_R01=53/53` on `cc643bb`; schema diff is additions only) |

Independent gate re-runs on `cc643bb` (not trusting the branch's own `RECONCILIATION.md`):
`ANALYSIS_RECORD_R01=53/53`, `CAP2_GATE=PASS` ("frozen outputs unchanged outside cap2's domain").

## The two changed body-wide sites (pre → post identity)

Both are in `pkey_GOST_ECcp_decrypt` (site `93dc5f6e3120481d`), `unsigned char wrappedKey[44]`
(decl independently confirmed from the CPG), and both are **body-wide** writes — NOT the packet's
labeled write (labeled line 75, `key_len`, a `pointer_deref`):

| dest | line | V1 `70805e2` | V1 `cc643bb` | V2 canonical |
|---|---|---|---|---|
| `wrappedKey + 8` | 54 | abstained / `capacity_relation_not_established` | rerouted / `delegated_to_stack_capacity_v2` | `deterministic_complete` (32 ≤ 36 remaining, byte array, offset 0) |
| `wrappedKey + 40` | 56 | abstained / `capacity_relation_not_established` | rerouted / `delegated_to_stack_capacity_v2` | `deterministic_complete` (4 ≤ 4 remaining, byte array, offset 0) |

## Promotion audit (assertion 5, in full — nothing hidden)

Across the **entire** V2 canonical output over all 276 packets: **4** `deterministic_complete`,
**0** `proven_oversized`.

| dest | fn | vuln? | source | note | delegated? |
|---|---|---|---|---|---|
| `ukm` (L20) | pkey_GOST_ECcp_encrypt | **True** | `unsigned char[8]` | 8 ≤ 8, offset 0 | no (pre-existing bare-stack) |
| `wrappedKey` (L52) | pkey_GOST_ECcp_decrypt | False | `unsigned char[44]` | 8 ≤ 44, offset 0 | no (pre-existing bare-stack) |
| `wrappedKey + 8` (L54) | pkey_GOST_ECcp_decrypt | False | `unsigned char[44]` | 32 ≤ 36, offset 8 | **yes (this change)** |
| `wrappedKey + 40` (L56) | pkey_GOST_ECcp_decrypt | False | `unsigned char[44]` | 4 ≤ 4, offset 40 | **yes (this change)** |

- The **2 bare-stack** promotions are pre-existing frozen V2 behaviour — present identically in the
  `70805e2` baseline V2 run (`baseline_promotions.json`), so the delegation change introduces **0**
  new bare-path promotions.
- The **2 delegated** promotions are the only new ones. Each is independently re-derived here as sound:
  a CPG-confirmed fixed **byte** array (`unsigned char[N]`), literal offset + literal width, `offset +
  width ≤ N`. Every promotion asserts only `write_length_within_destination_capacity` and carries
  `unaddressed_properties = [source_length_sufficiency, pointer_validity, lifetime]` — it is not a
  claim the operation is safe overall.
- **No false-safe.** None of the 4 promotions coincides with a labeled vulnerable write. The one
  vulnerable function here (`pkey_GOST_ECcp_encrypt`) has its labeled CVE site at line 100
  (`out_len`, a `pointer_deref`) — a write the scanner does not recognize at all (a miss), not one it
  promotes to safe. The promoted `ukm` write (line 20) is a different, benign body write.

## What this run does and does not establish

- **Does**: `cc643bb`'s delegation change reproduces the archived 45/45 and 13/20 numbers on a real,
  hash-verified cache; changes exactly the 2 predicted sites; keeps V2 canonical with V1 provenance;
  emits only schema-valid records under schema "2"; introduces no new or unjustified safe/oversized
  promotion; and leaves the frozen r01/cap2 gates green.
- **Does not**: constitute a new confirmatory recognition measurement. The 276-packet cache is the
  **consumed** 258-corpus development data. Any recognition/recall claim still requires a NEW, unseen
  held-out corpus. This is a regression/soundness verification of the delegation refactor only.

## Reproduce

```
# cache copied read-only to an immutable dir; regression + verify run against the copy
python3 dev_controls/emitgap/regression.py                       # 45/45, 13/20, PASS
python3 study/emission_gap_delegation_verify/verify_v2_delegation.py <sv> <tools> <cache> out.json
python3 study/emission_gap_delegation_verify/full_promotion_audit.py <sv> <tools> <cache> out.json
python3 study/emission_gap_delegation_verify/procC_assert.py     # all assertions PASS
```
