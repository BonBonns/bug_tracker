#!/usr/bin/env python3
"""NAPI-REACHABILITY-COMBINED-R01: the FINAL promotion, requiring all THREE independent
proofs before a worker-override native function is treated as an externally reachable
reportable root:

    export root established           (napi_export_root, R01)
  AND async registration / object identity established
  AND unique virtual override established   (virtual_dispatch_reachability, frozen)

Composition only -- it MODIFIES NOTHING frozen: it calls napi_export_root to produce the
`root_is_reachable` predicate and feeds that to the frozen
virtual_dispatch_reachability.promote_gated_by_root (never weakened), whose result already
requires the async-registration/object-identity chain AND the unique concrete override.
A native function full-name is in `virtual_proven(raw)` iff all three hold.

New reachability revision so frozen behavior stays reproducible: it defines its own
EXTENDED reachable-tier set (the frozen staged set PLUS
TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN) and its own applicability/enablement helpers that
use it -- staged_enablement.py and napi_status_integration.py are untouched.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import provenance  # noqa: E402
import staged_enablement as se  # noqa: E402
import virtual_dispatch_reachability as V  # noqa: E402
import napi_export_root as E  # noqa: E402

TIER = V.TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN

# NEW revision's reachable-tier set: the frozen staged set, plus the virtual-dispatch tier.
# The frozen se._EXTERNALLY_REACHABLE_TIERS is read, never mutated.
EXTENDED_REACHABLE_TIERS = frozenset(se._EXTERNALLY_REACHABLE_TIERS) | {TIER}


def virtual_proven(raw):
    """{function_full_name: evidence} for native functions that satisfy ALL THREE proofs
    on `raw`: export-root established (proof 1) gating the frozen virtual-dispatch result
    (proofs 2 and 3). Composition of the two frozen/independent revisions."""
    pred = E.root_reachable_predicate(raw)             # proof 1 -> predicate
    gated = V.promote_gated_by_root(raw, pred)         # proofs 2+3, gated by proof 1
    F = V.Facts(raw)
    return {F.methods[fid]["full_name"]: ev for fid, ev in gated.items()}


def method_fullname_map(raw):
    F = V.Facts(raw)
    return {mid: m["full_name"] for mid, m in F.methods.items()}


def apply_combined_reachability(record, raw, key="napi_status_findings"):
    """Sets reachability_status = TIER on every finding whose EFFECTIVE function is in the
    three-proof set; leaves others untouched (they keep whatever the base pipeline gave
    them). Returns the count elevated."""
    proven = set(virtual_proven(raw))
    id2name = method_fullname_map(raw)
    n = 0
    for f in record.get(key) or []:
        fid = f.get("caller_method_id", f.get("method_id"))
        full = id2name.get(fid)
        if full and full in proven:
            f["reachability_status"] = TIER
            f["reachability_evidence"] = {"combined_three_proofs": True,
                                          "tier": TIER}
            n += 1
    return n


def apply_combined_applicability(record, key="napi_status_findings",
                                 supported_apis=("napi_create_buffer",
                                                 "napi_create_buffer_copy")):
    """Raw-N-API applicability using the EXTENDED reachable-tier set (so the virtual tier
    counts). Same shape as napi_status_integration's rule; frozen module untouched."""
    applied = 0
    for f in record.get(key) or []:
        if not f.get("scanner_candidate"):
            continue
        exact_api = f.get("derived_from") or f.get("creation_call_name")
        if exact_api not in supported_apis:
            continue
        targets = f.get("output_targets") or []
        required_resolved = (any(t.get("required") for t in targets)
                             and all(t.get("referent_id") is not None
                                     for t in targets if t.get("required")))
        if not required_resolved:
            continue
        if not (f.get("provenance") or {}).get("resolved"):
            continue
        if f.get("reachability_status") not in EXTENDED_REACHABLE_TIERS:
            continue
        if f.get("applicability_status") == "APPLICABLE":
            continue
        f["applicability_status"] = "APPLICABLE"
        provenance.finalize_reportability(f, f.get("scanner_candidate", False))
        applied += 1
    return applied


def apply_combined_enablement(record, key="napi_status_findings"):
    """Staged enablement using the EXTENDED tier set. Never flips a formula-False finding
    to True; only narrows. Returns record."""
    for f in record.get(key) or []:
        if f.get("reachability_status") not in EXTENDED_REACHABLE_TIERS:
            if f.get("reportable"):
                f["reportable"] = False
            f["stage_status"] = "REACHABILITY_REQUIRED_FOR_REPORTING"
        else:
            f["stage_status"] = "STAGE_ENABLED"
    return record
