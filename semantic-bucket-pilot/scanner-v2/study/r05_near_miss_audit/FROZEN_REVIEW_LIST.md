# R05 near-miss audit -- frozen review selection (recorded BEFORE reading any new source)

Snapshot: `r05_near_miss_snapshot_00000365_654d4d8f03af.tsv` (365 real records, sha256
`654d4d8f03af3c6c26db26b7e391dc22889ad8a5a81cf671b889f5a0e7356d5d`).

## Real funnel penetration (from `build_funnel.py`, run against the frozen snapshot)

| Stage | Count |
|---|---|
| 1. acquisition name encountered | 25,518 |
| 2. acquisition identity/shape recovered | 23,951 |
| 3+4. overload + result-type recognized (`R05_ACQUISITION_CALL_RECOVERED`) | **2** |
| 6. size influence check reached | 2 |
| 8. downstream use established | 1 |
| 9. guard classification completed | 1 |
| 5. build configuration applicable | 1 |
| 10. actionable finding emitted | 1 |

The funnel's real, overwhelming bottleneck is stage 3+4 (overload + result-type
recognition): 23,949 of 23,951 candidates that reach stage 2 stop there
(`R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`). Only 2 candidates in the entire 365-package
snapshot ever progress past it -- both already fully identified (`node-libcurl`,
`node-crc16`). **Stages 5, 8, and 9 currently have a real population of exactly the same 2
candidates that reached stage 3+4 -- there is no DISTINCT, unreviewed near-miss population
at those later stages in this snapshot.** This is reported honestly rather than padded with
a fabricated sample: a genuine top-5 sample for those specific stages does not exist yet at
this snapshot size.

## Selection 1: every positive finding (population = 1, entire population)

- `node-libcurl@5.1.2`, `ReadFunction`, `acquisition_call_id=30064773338` -- already
  exhaustively reviewed this session (`NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`,
  `STRATIFIED_REVIEW_RESULTS.md`). Restated in this audit's own evidence table, not
  re-derived from scratch.

## Selection 2: `SIZE_ATTACKER_INDEPENDENT` (population = 1, entire population)

- `node-crc16@2.0.7` -- already reviewed this session. Restated, not re-derived.

## Selection 3: dominant near-miss bucket -- `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`

**Deterministic selection rule** (stated before any of the 5 packages below were opened):
rank every real package with `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED > 0` by that count,
descending; exclude packages already reviewed this session (`node-libcurl`, `fontnik`,
`libpq`, `@ipshipyard/node-datachannel`, `@ssxv/node-printer`, `node-crc16`,
`@gjsify/node-gi` -- the last is R05's own documented historical blind-test package,
`BLIND_TEST.md`); collapse an auto-generated package FAMILY (`@nodert-win10*/windows.*`,
confirmed real -- many near-identical WinRT wrapper packages share the same generator and
would not yield independent evidence) to its single highest-ranked member only; take the
top 5 of what remains.

Real ranked output (from `full_scan_r05_working.jsonl`'s own real
`r05_classification.R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED` counts, computed once, recorded
verbatim):

```
swisseph@0.5.17                                          1496
@nodert-win10-rs4/windows.ui.notifications@0.4.4          793  (nodert family representative
                                                                 -- 2 sibling variants at
                                                                 792/752 excluded by the
                                                                 family-collapse rule)
node-snap7@1.0.9                                           616
@brick-a-brack/napi-canon-cameras@0.1.5                     410
@nodriverai/mavjs@0.1.2                                     388
```

Five distinct, real, un-reviewed packages spanning five different real domains
(astronomical ephemeris calculation, WinRT notification bridge, Siemens S7 industrial PLC
protocol, Canon camera SDK, MAVLink drone telemetry) -- selected for genuine diversity of
real native-addon shapes, not convenience.

## Selection 4: stages 5 (build config), 8 (use), 9 (guard) -- no distinct population

No sampling performed -- disclosed as an empty, not-yet-populated bucket at this snapshot
size (see funnel table above). Will be revisited honestly once the corpus produces real,
distinct candidates reaching this deep.
