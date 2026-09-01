#!/usr/bin/env python3
"""NAPI-STATUS-INTEGRATION-R01: wires NAPI-STATUS-R02 (napi_status_verdict_r02.py,
findings under the record key `napi_status_findings`) into the real pipeline stages --
provenance enrichment, JS/native reachability, applicability, exact-match
adjudication, staged enablement, and a NEW aggregator revision -- following the Nan
integration's additive precedent. NOTHING frozen is rewritten: `provenance.py`,
`reachability_tier.py`, `applicability_gate.py`, `adjudication_registry.py`,
`staged_enablement.py`, and `six_property_aggregator.py` are imported and REUSED;
this module only adds the napi_status entries around them, and the new aggregator
revision delegates the six frozen properties to `six_property_aggregator.
aggregate_record` unchanged (the task #34 schema is not touched).

CANDIDATE VOCABULARY (the correction this module exists to make exact). Both of these
satisfy the property's candidate definition -- the caller-side identifier proves the
status was discarded, the required output escaped, AND the caller used that output
afterward, which is every element of the property, established interprocedurally:

    STATUS_GUARD_MISSING              (verdict; intraprocedural sub_reasons)
    STATUS_DISCARDED_OUTPUT_USED_IN_CALLER   (its caller-side sub_reason identifier)

In napi_status_verdict_r02.py's record shape the caller-side finding carries
verdict == "STATUS_GUARD_MISSING" AND sub_reason ==
"STATUS_DISCARDED_OUTPUT_USED_IN_CALLER" -- the allowlist below enumerates BOTH
identifiers as exact strings so no narrower intraprocedural reading can ever silently
discard the caller-side finding, and it FAILS CLOSED LOUDLY: a STATUS_GUARD_MISSING
record with an unrecognized sub_reason is neither dropped nor admitted -- it is
counted as CANDIDATE_VOCABULARY_UNRECOGNIZED (gated to zero in
check_napi_status_integration.py). Every abstention (OUTPUT_ESCAPES_CALLER_ANALYSIS_
REQUIRED included) and every NO_OUTPUT_USE* / STATUS_PROPAGATED* / *_ESTABLISHED
record is a NON-candidate.

EFFECTIVE FUNCTION IDENTITY: for a caller-side finding, the function whose source
path, content hash, and JS reachability matter is the CALLER (where the use is),
identified by the additive `caller_method_id`/`caller_call_id`/`unguarded_use_node`
fields R02 preserves; intraprocedural findings use `method_id` as before.
`effective_function_id()` is the single accessor every stage here uses.

APPLICABILITY FOR RAW N-API (deliberately different from Resource Guard's): a
candidate is APPLICABLE iff (1) the creation call is a supported EXACT API,
(2) every required output role resolved (both already implied by the candidate
verdict, re-checked belt-and-braces), (3) provenance resolved, (4) the effective
function's reachability tier is in staged_enablement's own allowlist. There is NO
exception-configuration requirement: raw N-API (`extern "C"`) reports failure through
its napi_status return value regardless of the C++ exception build configuration --
that premise belongs to the node-addon-api C++ wrapper contract (R04+), not here.

ENABLEMENT: DIAGNOSTIC-ONLY. `NAPI_STATUS_ENABLED = False` until a real package
exercises the property's positive path -- the compiled fixtures establish mechanism,
not portability (NAPI_STATUS_R02.md's own evidence table). enforce() therefore forces
reportable=False on every finding with stage_status
"STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY", exactly like run_diagnostic_100's blanket, but
per-property and disclosed. The reportability MACHINERY is still fully computed and
gated first (the controls prove both candidate identifiers CAN become reportable, and
that every abstention cannot), so enabling later is a one-line, evidence-cited change
that flips no logic.

Claims boundary: unchanged and load-bearing -- reportable=True here would mean
"eligible gated scanner candidate", never a vulnerability/impact claim (provenance.py
TERMINOLOGY BOUNDARY applies verbatim).
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import provenance  # noqa: E402
import reachability_tier  # noqa: E402
import staged_enablement as se  # noqa: E402
import six_property_aggregator as agg6  # noqa: E402

NAPI_STATUS_KEY = "napi_status_findings"

SUPPORTED_EXACT_APIS = ("napi_create_buffer", "napi_create_buffer_copy")

# The EXACT candidate allowlist -- see module docstring. Keyed identifiers, never
# shapes or prefixes.
CANDIDATE_VERDICT = "STATUS_GUARD_MISSING"
CANDIDATE_SUB_REASONS = frozenset({
    # intraprocedural
    "NO_RELATED_CHECK",
    "STATUS_DISCARDED",
    "RELATED_CHECK_AFTER_USE",
    "NON_TERMINATING_OR_BYPASSED_FAILURE_PATH",
    "UNRELATED_CHECK_ONLY",
    # caller-side -- proves discard + escape + caller use; a full candidate
    "STATUS_DISCARDED_OUTPUT_USED_IN_CALLER",
})

NAPI_STATUS_ENABLED = False  # diagnostic-only until a real package exercises the
                              # positive path -- see module docstring / R02 evidence
                              # table. Flip only with a cited real-package positive.

# Empty EXACT-MATCH adjudication registry section, same discipline as
# adjudication_registry.py: entries require a real, individually-documented manual
# review; matching is exact on (package_name, version, NAPI_STATUS_KEY, site_id)
# where site_id is the stable textual identity attached by enrich (node ids are not
# stable across fact regenerations; names/paths/lines/API are).
NAPI_STATUS_KNOWN_ADJUDICATIONS = {}


def effective_function_id(f):
    """The function whose source location and reachability govern this finding: the
    CALLER for a caller-side finding, the site's own method otherwise."""
    return f.get("caller_method_id", f.get("method_id"))


def _site_id(f):
    base = (f"{f.get('method_name')}:{f.get('file')}:{f.get('line')}:"
            f"{f.get('creation_call_name')}")
    if f.get("caller_method_id") is not None:
        base += f"->used_in:{f.get('caller_method')}:{f.get('unguarded_use_line')}"
    return base


def classify_candidate(f):
    """Returns 'CANDIDATE', 'NON_CANDIDATE', or 'CANDIDATE_VOCABULARY_UNRECOGNIZED'
    (a STATUS_GUARD_MISSING whose sub_reason is not in the exact allowlist -- fails
    closed as non-candidate but is surfaced loudly, never silently dropped or
    admitted)."""
    if f.get("verdict") != CANDIDATE_VERDICT:
        return "NON_CANDIDATE"
    if f.get("sub_reason") in CANDIDATE_SUB_REASONS:
        return "CANDIDATE"
    return "CANDIDATE_VOCABULARY_UNRECOGNIZED"


def is_candidate(f):
    return classify_candidate(f) == "CANDIDATE"


def enrich_napi_status(record, cpp_raw_dir, manifest, pkg_dir):
    """Provenance enrichment for napi_status_findings, reusing provenance.py's own
    enrich_finding/finalize_reportability verbatim (item: both candidate identifiers
    enter provenance enrichment). Uses the EFFECTIVE function id, so a caller-side
    finding's source_path/content_hash are the caller's -- where the cited use is.
    Attaches site_id (stable textual identity) and candidate_vocabulary (the loud
    fail-closed classification). Returns the count of vocabulary-unrecognized
    records so a driver can gate on zero."""
    method_file_map = provenance.load_method_file_map(cpp_raw_dir)
    unrecognized = 0
    for f in record.get(NAPI_STATUS_KEY) or []:
        vocab = classify_candidate(f)
        f["candidate_vocabulary"] = vocab
        if vocab == "CANDIDATE_VOCABULARY_UNRECOGNIZED":
            unrecognized += 1
        f["site_id"] = _site_id(f)
        provenance.enrich_finding(f, effective_function_id(f), method_file_map,
                                   manifest, pkg_dir, "effective_function_id")
        provenance.finalize_reportability(f, vocab == "CANDIDATE")
    return unrecognized


def apply_napi_status_reachability(record, js, cpp):
    """JS/native reachability for the EFFECTIVE caller function, reusing
    reachability_tier's own classifier (same tiers, same evidence shapes) -- never a
    napi-special reimplementation."""
    facts_available = bool(js.get("calls")) and bool(cpp.get("functions"))
    table = reachability_tier.build_registration_table(cpp) if facts_available else {}
    linked, _ = (reachability_tier.link_js_calls(js, cpp, table)
                 if facts_available else ([], []))
    clean_edges = (reachability_tier.build_clean_call_edges(cpp)
                   if facts_available else {})
    fn_names = ({f["id"]: f.get("full_name") for f in cpp.get("functions", [])}
                if facts_available else {})
    method_ref_targets = (reachability_tier.resolve_method_ref_targets(cpp)
                          if facts_available else {})
    init_ids = ({f["id"] for f in cpp.get("functions", []) if f.get("name") == "Init"}
                if facts_available else set())
    for f in record.get(NAPI_STATUS_KEY) or []:
        fid = effective_function_id(f)
        if fid is None:
            f["reachability_status"] = reachability_tier.REACHABILITY_UNRESOLVED
            f["reachability_evidence"] = None
            continue
        f.update(reachability_tier.classify_function_reachability(
            fid, table, linked, facts_available, clean_edges, fn_names,
            method_ref_targets, init_ids))
    return record


def apply_napi_status_applicability(record):
    """Raw-N-API applicability (see module docstring): supported exact API AND
    required outputs resolved AND candidate AND provenance resolved AND effective
    function's reachability tier in staged_enablement's own allowlist. NO
    exception-configuration requirement -- that premise is the C++ wrapper
    contract's, not raw N-API's. Only ever raises NOT_YET_DETERMINED to APPLICABLE;
    never lowers anything."""
    applied = 0
    for f in record.get(NAPI_STATUS_KEY) or []:
        if not is_candidate(f) or not f.get("scanner_candidate"):
            continue
        # a derived wrapper site's creation_call_name is the WRAPPER's own name; the
        # exact underlying API is recorded in derived_from by the wrapper registry.
        exact_api = f.get("derived_from") or f.get("creation_call_name")
        if exact_api not in SUPPORTED_EXACT_APIS:
            continue
        targets = f.get("output_targets") or []
        required_resolved = all(
            t.get("referent_id") is not None
            for t in targets if t.get("required")) and any(
            t.get("required") for t in targets)
        if not required_resolved:
            continue
        if not (f.get("provenance") or {}).get("resolved"):
            continue
        if f.get("reachability_status") not in se._EXTERNALLY_REACHABLE_TIERS:
            continue
        if f.get("applicability_status") == "APPLICABLE":
            continue
        f["applicability_status"] = "APPLICABLE"
        provenance.finalize_reportability(f, f.get("scanner_candidate", False))
        applied += 1
    return applied


def apply_napi_status_adjudications(record, package_name, version):
    """Exact-match adjudication application over the (currently EMPTY) registry
    section above -- same discipline as adjudication_registry.py: exact tuple match
    only, applies the recorded status, recomputes reportable through the one
    formula. Returns count applied."""
    applied = 0
    for f in record.get(NAPI_STATUS_KEY) or []:
        entry = NAPI_STATUS_KNOWN_ADJUDICATIONS.get(
            (package_name, version, NAPI_STATUS_KEY, f.get("site_id")))
        if not entry:
            continue
        f["adjudication_status"] = entry["adjudication_status"]
        f["adjudication_citation"] = entry.get("citation")
        f["adjudication_reason"] = entry.get("reason")
        provenance.finalize_reportability(f, f.get("scanner_candidate", False))
        applied += 1
    return applied


def enforce_napi_status_enablement(record):
    """Staged enablement for this property, mirroring staged_enablement.py's own
    two-gate discipline with an exact property/verdict allowlist:
      - property not enabled (NAPI_STATUS_ENABLED is False -- diagnostic-only):
        forces reportable=False, stage_status='STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY'.
      - enabled but reachability tier not in the allowlist: forces
        reportable=False, stage_status='REACHABILITY_REQUIRED_FOR_REPORTING'.
      - enabled with an allowed tier: reportable left exactly as the formula
        computed (never flipped False->True); stage_status='STAGE_ENABLED'.
    Also, regardless of enablement: a record whose candidate_vocabulary is not
    'CANDIDATE' can never stay reportable (belt-and-braces on the exact
    allowlist)."""
    for f in record.get(NAPI_STATUS_KEY) or []:
        if f.get("candidate_vocabulary") != "CANDIDATE" and f.get("reportable"):
            f["reportable"] = False
        if not NAPI_STATUS_ENABLED:
            if f.get("reportable"):
                f["reportable"] = False
            f["stage_status"] = "STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY"
            continue
        if f.get("reachability_status") not in se._EXTERNALLY_REACHABLE_TIERS:
            if f.get("reportable"):
                f["reportable"] = False
            f["stage_status"] = "REACHABILITY_REQUIRED_FOR_REPORTING"
            continue
        f["stage_status"] = "STAGE_ENABLED"
    return record


# --- the NEW aggregator revision (task #34's six-property schema untouched) ------------
AGGREGATOR_REVISION = "seven-property-aggregate/r02"


def aggregate_record_r02(record, enabled_properties):
    """Aggregator REVISION: delegates the six frozen properties (plus nan) to
    six_property_aggregator.aggregate_record VERBATIM -- same keys, same counts, same
    disabled-property invariant, byte-identical sub-summary -- then adds the
    napi_status_findings row under the same {raw_count, reportable_count, enabled,
    disabled_reason} shape and recomputes the combined totals. HARD INVARIANT
    (mirroring the six-property one): while NAPI_STATUS_ENABLED is False, a
    reportable napi_status finding in the aggregate raises -- enforce_napi_status_
    enablement() must have run, exactly as staged_enablement must have for the six."""
    summary = agg6.aggregate_record(record, enabled_properties)
    items = record.get(NAPI_STATUS_KEY) or []
    reportable_count = sum(1 for f in items if f.get("reportable") is True)
    if not NAPI_STATUS_ENABLED and reportable_count:
        raise AssertionError(
            f"INVARIANT VIOLATION: {NAPI_STATUS_KEY} is DIAGNOSTIC-ONLY "
            f"(NAPI_STATUS_ENABLED=False) but has {reportable_count} reportable "
            "finding(s) -- enforce_napi_status_enablement() did not run on this "
            "record, or was bypassed.")
    summary[NAPI_STATUS_KEY] = {
        "raw_count": len(items),
        "reportable_count": reportable_count,
        "enabled": NAPI_STATUS_ENABLED,
        "disabled_reason": None if NAPI_STATUS_ENABLED else (
            "diagnostic-only: no real package has exercised this property's "
            "positive path yet -- compiled fixtures establish mechanism, not "
            "portability (NAPI_STATUS_R02.md, evidence status)"),
    }
    summary["_totals"] = {
        "total_raw": sum(e["raw_count"] for k, e in summary.items() if k != "_totals"),
        "total_reportable": sum(e["reportable_count"] for k, e in summary.items()
                                 if k != "_totals"),
    }
    summary["_aggregator_revision"] = AGGREGATOR_REVISION
    return summary
