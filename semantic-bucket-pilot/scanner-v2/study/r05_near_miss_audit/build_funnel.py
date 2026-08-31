#!/usr/bin/env python3
"""R05 near-miss audit -- Step 2/3: builds the full decision funnel from the REAL, frozen
snapshot (immutable, checksum-verified) and ranks near-miss candidates. Read-only against
the snapshot; never touches the live scan or its working file.

Funnel stage mapping (documented, not assumed) -- derived from directly reading
resource_guard_verdict_r05.py's own real classification-counter call sites. The REAL code
execution order does NOT exactly match the requested conceptual funnel order in one place,
disclosed here rather than misrepresented: SIZE_ATTACKER_INDEPENDENT is checked BEFORE
downstream-use/guard-dominance analysis, and the applicability (build-config) gate is
checked AFTER the dominance walk completes, not before. The mapping below reflects what each
real check actually verifies, not the literal code order.

  1. acquisition name encountered       -> ACQUISITION_NAME_MATCH_CANDIDATE
  2. acquisition identity recovered     -> R05_RECOVERY_CANDIDATE (name + the specific real
                                            <unresolvedNamespace>/<unresolvedSignature> shape
                                            recognized) OR R04's own resolved-qualifier match
                                            (ACQUISITION_CALL_FOUND -- real corpus rate: 0,
                                            confirmed, since c2cpg never resolves these
                                            qualifiers at all -- see R05_DESIGN.md)
  3. contract and overload recognized   -> passing R05_RECOVERY_ARITY_UNRECOGNIZED /
                                            R05_RECOVERY_ARG_ROLE_UNRECOGNIZED (real arity +
                                            arg0 env-type role match this specific curated
                                            overload)
  4. result type/object identity        -> passing R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED
     established                           (LHS identifier's own resolved type is a real,
                                            curated Buffer form)
     [3+4 combined pass]                -> R05_ACQUISITION_CALL_RECOVERED
  5. build configuration applicable     -> NOT CONTRACT_NOT_APPLICABLE / BUILD_CONFIGURATION_
                                            CONFLICT / BUILD_CONFIGURATION_UNRESOLVED (real
                                            code order: checked AFTER stage 9 below, not before
                                            -- disclosed, not hidden)
  6. size influence found               -> NOT SIZE_ATTACKER_INDEPENDENT (real code order:
                                            checked directly after stage 4, before 7-9)
  7. source boundary established        -> backward_attacker_trace's own real result (R05 has
                                            no source_boundary_evidence field at all -- this
                                            stage's real distinction only exists under R06)
  8. downstream use established         -> NOT RESOURCE_ACQUIRED_NO_USE
  9. guard classification completed     -> NOT VALUE_ACQUISITION_SEMANTICS_UNRESOLVED /
                                            PREDICATE_UNRECOGNIZED_BRANCH_SHAPE /
                                            PREDICATE_INVERTED_POLARITY /
                                            PREDICATE_FAILURE_BRANCH_DOES_NOT_TERMINATE
  10. actionable finding emitted        -> verdict == VALUE_ACQUISITION_GUARD_MISSING

Only candidates that produce a real per-instance FINDING RECORD (not just a classification
counter increment) can be individually ranked/reviewed by source -- see this script's own
`RECORD_BEARING_VERDICTS`. A counter-only rejection (e.g. ACQUISITION_SIGNATURE_UNRECOGNIZED,
R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED) carries no acquisition_call_id/method_name in this
schema at all -- reviewing a SPECIFIC instance from those buckets requires regenerating facts
for that one selected package (Step 4 of the audit, done separately, only for packages
actually selected for review).
"""
import hashlib
import json
import sys
from collections import Counter, defaultdict

SNAPSHOT = sys.argv[1] if len(sys.argv) > 1 else \
    "r05_near_miss_snapshot_00000365_654d4d8f03af.tsv"

# Real per-instance finding records exist ONLY for these verdicts (confirmed by reading
# every real `findings.append(...)` site in resource_guard_verdict_r05.py).
RECORD_BEARING_VERDICTS = {
    "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED", "CONTRACT_NOT_APPLICABLE",
    "BUILD_CONFIGURATION_CONFLICT", "BUILD_CONFIGURATION_UNRESOLVED",
    "VALUE_ACQUISITION_GUARD_MISSING", "VALUE_ACQUISITION_GUARD_ESTABLISHED",
}


def load_records(path):
    raw = open(path, "rb").read()
    checksum = hashlib.sha256(raw).hexdigest()
    lines = raw.decode("utf-8").splitlines()
    recs = [json.loads(l) for l in lines if l.strip()]
    return recs, checksum, len(lines)


def main():
    recs, checksum, n_lines = load_records(SNAPSHOT)
    print(f"snapshot: {SNAPSHOT}")
    print(f"sha256: {checksum}")
    print(f"row_count (real records): {len(recs)} (raw lines: {n_lines})")
    print()

    status_dist = Counter(r["status"] for r in recs)
    print("pipeline status distribution:", dict(status_dist))
    print()

    agg = Counter()
    per_pkg_agg = {}
    all_finding_records = []  # (pkg, version, verdict, finding_dict)
    for r in recs:
        cls = r.get("r05_classification") or {}
        per_pkg_agg[(r["package_name"], r["version"])] = dict(cls)
        for k, v in cls.items():
            agg[k] += v
        for f in (r.get("r05_findings") or []):
            all_finding_records.append((r["package_name"], r["version"], f.get("verdict"), f))

    print("=== AGGREGATE REAL CLASSIFICATION COUNTS (across all real, complete records) ===")
    for k, v in agg.most_common():
        print(f"  {k}: {v}")
    print()

    # Real funnel: candidates surviving into each stage, computed from the aggregate counters.
    n_name_match = agg.get("ACQUISITION_NAME_MATCH_CANDIDATE", 0)
    n_shape_recovered = agg.get("R05_RECOVERY_CANDIDATE", 0) + agg.get("ACQUISITION_CALL_FOUND", 0)
    n_result_type_ok = agg.get("R05_ACQUISITION_CALL_RECOVERED", 0) + agg.get("ACQUISITION_CALL_FOUND", 0)
    # Overload/arity/arg-role rejections happen BEFORE result_type success is counted in the
    # aggregate (R05_ACQUISITION_CALL_RECOVERED already implies arity+arg-role passed too --
    # this scanner's own real code checks result_type FIRST, then arity, then arg-role, so
    # "stage 3 (overload)" and "stage 4 (result type)" are only jointly observable via this
    # one combined counter in the real schema -- disclosed, not a limitation invented here.
    n_overload_and_type_ok = n_result_type_ok
    n_size_influence_checked = n_overload_and_type_ok  # all of these proceed to the size check
    n_size_not_independent = n_overload_and_type_ok - agg.get("SIZE_ATTACKER_INDEPENDENT", 0)
    # Beyond this point, real records exist (RESOURCE_ACQUIRED_NO_USE has NO per-instance
    # record in this schema either -- pure counter, disclosed).
    n_use_established = n_size_not_independent - agg.get("RESOURCE_ACQUIRED_NO_USE", 0)
    n_guard_classified = n_use_established - agg.get("VALUE_ACQUISITION_SEMANTICS_UNRESOLVED", 0) \
        - agg.get("PREDICATE_UNRECOGNIZED_BRANCH_SHAPE", 0) - agg.get("PREDICATE_INVERTED_POLARITY", 0) \
        - agg.get("PREDICATE_FAILURE_BRANCH_DOES_NOT_TERMINATE", 0)
    n_build_config_applicable = n_guard_classified - agg.get("CONTRACT_NOT_APPLICABLE", 0) \
        - agg.get("BUILD_CONFIGURATION_CONFLICT", 0) - agg.get("BUILD_CONFIGURATION_UNRESOLVED", 0)
    n_actionable = agg.get("VALUE_ACQUISITION_GUARD_MISSING", 0)

    print("=== FUNNEL (aggregate, real counters) ===")
    print(f"  1. acquisition name encountered:        {n_name_match}")
    print(f"  2. acquisition identity/shape recovered: {n_shape_recovered}")
    print(f"  3+4. overload+result-type recognized:    {n_result_type_ok}")
    print(f"  6. size influence check reached:         {n_size_influence_checked}")
    print(f"     (SIZE_ATTACKER_INDEPENDENT rejected):  {agg.get('SIZE_ATTACKER_INDEPENDENT', 0)}")
    print(f"  8. downstream use established:           {n_use_established}")
    print(f"     (RESOURCE_ACQUIRED_NO_USE rejected):   {agg.get('RESOURCE_ACQUIRED_NO_USE', 0)}")
    print(f"  9. guard classification completed:       {n_guard_classified}")
    print(f"  5. build configuration applicable:       {n_build_config_applicable}")
    print(f"     (CONTRACT_NOT_APPLICABLE):             {agg.get('CONTRACT_NOT_APPLICABLE', 0)}")
    print(f"     (BUILD_CONFIGURATION_CONFLICT):        {agg.get('BUILD_CONFIGURATION_CONFLICT', 0)}")
    print(f"     (BUILD_CONFIGURATION_UNRESOLVED):      {agg.get('BUILD_CONFIGURATION_UNRESOLVED', 0)}")
    print(f" 10. actionable finding emitted:            {n_actionable}")
    print()

    print("=== ALL REAL PER-INSTANCE FINDING RECORDS (any verdict) ===")
    for pkg, ver, verdict, f in all_finding_records:
        print(f"  {pkg}@{ver}: verdict={verdict} method={f.get('method_name')} "
              f"acquisition_call_id={f.get('acquisition_call_id')}")
    print(f"  total: {len(all_finding_records)}")
    print()

    print("=== PACKAGES REACHING R05_ACQUISITION_CALL_RECOVERED (deepest funnel penetration "
          "observable in aggregate form) ===")
    for (pkg, ver), cls in per_pkg_agg.items():
        if cls.get("R05_ACQUISITION_CALL_RECOVERED"):
            print(f"  {pkg}@{ver}: {cls}")


if __name__ == "__main__":
    main()
