# This session's changes (field storage identity + capacity keying)

Shipped code (live in the tree):
- tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py  (normalizer 67515a0fa69934b6)
    FIELD-ID-R02a  : emit FieldStorageIdentity = (base_storage_id, member_decl_id)
    FIELD-ID-R02a.1: base-type-scoped member resolution (recovers name-ambiguous members)
    R02b           : capacity consumes the field identity (producer side)
    CAP-KEY-R01    : capacity facts carry storage_identity_kind + field_storage_key
- tools/oob_write_verdict.py  : field-aware capacity JOIN (VALUE_ID by sid>=0, FIELD by call_id;
                                sentinel storage id -1 is NEVER a join key)
- tools/capacity_controls.py + tests/gates/guard-r01/capacity_controls.py : GUARD-R01 capacity
                                control migrated from a pinned source string to an INVARIANT
                                assertion; CAPACITY_CONTROLS 11/11

Engine-core (Java) UNCHANGED: 7ad2880e04e84fd5.

Verified state at package time:
    canonical 31/31, REGRESSIONS 0, GUARD-R01 PASS
    tcpdump OOB_WRITE 13 (11 frozen + 2 CONSTANT_EXTENT safe residuals, adjudicated)
    raft OOB_WRITE 8, OOB_COMPARE 0

Milestone docs (this dir): FIELD_ID_R01/R02A/R02A1/R02B, ARRAY_DIM_R01,
CONST_EXPR_R01_AND_ARRAY_DIM_CORRECTION, TOR_SCAN_R01, TOR_TU_R01, R02B_PROMOTION_REPLAY,
CAP_KEY_R01, TOR_CAND_R01.

Teeth fixtures: tests/fixtures/session-teeth/  (fieldidtest, typefidtest, capfidtest,
capkeytest, constexpr_test).

To run: see HOW_TO_RUN.md (needs Joern + JOERN_HOME; python3 tests/run_all.py).
