# DEV: emission-gap fix — recognized memcpy with identifiable non-bare destination

**Development branch `claude/emission-gap-fix`.** This is scanner development motivated by the
held-out misses; per the discipline, any recognition improvement measured on the consumed 258-site
corpus is a DEVELOPMENT result and a NEW, unseen held-out corpus is required for any confirmatory
generalization claim. The 258 corpus is used here only as REGRESSION evidence.

## The gap (root cause)

`oob_runtime_capacity_verdict.analyze_operations` recognized a memcpy-family sink but then
**dropped the operation** when the destination was not a bare pointer identifier
(`if not re.fullmatch(r'[A-Za-z_]\w*', dest): continue` — "bare pointer destination only, MVP").
Of the 19 held-out group-A cases (recognized `memcpy`, capacity absent), **18 had non-bare
destinations** — struct/union members (`session->input_buf`, `vs_param_set->ie`), address-of
(`&obj`, `&StreamConfig`), or pointer arithmetic (`base + off`, `ie->ie_buffer + le16_to_cpu(...)`).
These were silently dropped, so the recognized operation never reached the router. (A bare
destination with no reaching allocation already emitted `abstained/required_evidence_absent`.)

## The fix

For a recognized sink whose destination is IDENTIFIABLE but non-bare, emit an EXPLICIT
ABSTENTION instead of dropping:

    analysis_status     = abstained
    reason_code         = required_evidence_absent
    missing_requirement = destination_capacity
    destination_form    = member_or_expression

It is **never promoted** (this producer does not establish capacity for a non-bare destination),
so soundness is preserved — the operation becomes visible to the router with the exact missing
requirement named, nothing more. The bare-destination + no-allocation path also now carries
`missing_requirement = destination_capacity` explicitly. The with-allocation paths
(deterministic_complete / open_candidate) are unchanged.

## Validation

- **Synthetic controls** (`dev_controls/emitgap/{controls.c,test.py}`, 6/6 PASS): member,
  address-of, pointer-arithmetic, and bare-no-alloc destinations -> abstained +
  `missing_requirement=destination_capacity`; bare+alloc same-width -> deterministic_complete
  (unchanged); bare+alloc different-width -> open_candidate (unchanged).
- **Frozen suite unchanged**: `ANALYSIS_RECORD_R01 = 53/53`; `CAP2_GATE = PASS` ("frozen outputs
  unchanged outside cap2's domain"). The change is additive (new records for previously-dropped
  non-bare destinations + a new field); no existing bare-identifier record changed.
- **Regression on the consumed corpus (development evidence only)**: all **19/19** held-out
  group-A sites now emit `abstained / required_evidence_absent / missing_requirement=
  destination_capacity` instead of silently dropping.

## Not done here (scope)

- The 28 unsupported-sink cases (`memset`/`snprintf`/`sprintf`/`strcpy`/`strncpy`) still need
  sink contracts; the 89 unsupported-form (general index/deref) cases need new models; the 69
  parse-collapse cases need better function-packet parsing or full-repository builds. Those are
  separate development items.
- No confirmatory recognition number is claimed from this change. Establishing that the fix
  improves generalization requires a fresh held-out corpus.
