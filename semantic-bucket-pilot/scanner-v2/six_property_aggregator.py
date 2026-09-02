#!/usr/bin/env python3
"""SIX-PROP-AGG-R01 (task #47, a precursor to task #34): combines all six properties -- Resource
Guard (r04_findings/r05_findings/r06_findings) plus the five staged properties
(LOCK_BALANCE/PROTECTED_FIELD/OOB_WRITE/OOB_INDEX_WRITE/OOB_READ/OOB_COMPARE) -- into one
aggregate summary, per direct instruction:
  - Resource Guard: enabled.
  - Lock Balance: enabled.
  - Protected Field: enabled.
  - OOB Write / OOB Index Write: enabled ONLY for externally reachable tiers -- internal-
    unregistered stays diagnostic. This is exactly what staged_enablement.py's own reachability
    gate now enforces (task #47's own correction: TIER_INTERNAL_UNREGISTERED no longer clears
    the gate, only TIER_JS_CALL_PROVEN/TIER_REGISTERED_NOT_JS_CALLED do) -- this module does not
    re-implement that logic, it trusts the upstream result.
  - OOB Read: enabled.
  - OOB Compare: explicitly disabled, with its reason recorded (task #33's own real
    investigation) -- never silently omitted, never silently enabled by this or a future step.

THIS MODULE DOES NOT COMPUTE REPORTABILITY. It is a pure aggregation/summary step over a record
that has ALREADY been through the real pipeline, in this exact order:
  1. provenance.enrich_record()            (task #35 -- the reportable formula itself)
  2. reachability_tier.classify_record_reachability()   (task #32 -- attaches reachability_status
     to the five staged property keys, never r04/r05/r06)
  3. staged_enablement.enforce_staged_enablement()       (tasks #36-40, #47 -- the corrected
     reachability gate; never touches r04/r05/r06 either)
Each property's own `reportable` field, once that pipeline has run, is already the real,
authoritative answer -- this module only reads it and organizes it into one combined view,
never recomputing or overriding it. "Enabled" here means "trusted and included in the combined
count," not "forced reportable."

HARD INVARIANT, verified not just claimed: a DISABLED property (currently only OOB_COMPARE)
must NEVER contribute a reportable finding to the aggregate. aggregate_record() raises
(never silently continues) if this is ever violated -- that would mean staged_enablement.py's
own gate failed, a bug this module is specifically positioned to catch before it reaches a real
report.

ADDENDUM (Nan Resource Guard integration): `nan_findings` (resource_guard_verdict_nan.py, frozen
per study/nan_capability/NAN_CAPABILITY_FREEZE.md) is now included too, treated the same as
Resource Guard's own three keys -- always "enabled," never gated by staged_enablement.py (which
only ever touches STAGED_KEYS). Its own applicability rule lives in applicability_gate.py,
distinct from R04/R05/R06's build-configuration premise (Nan's own module docstring: that
premise "does not hold for `Nan::NewBuffer`/`Nan::CopyBuffer`'s real `.ToLocalChecked()` idiom").

ADDENDUM (Serialize DoS integration, roadmap step 8, third of 4 JS/TS classes): `serialize_dos_findings`
(serialize_dos_r03.py's own `derive()`, frozen -- merged into develop unmodified from a separate,
parallel session's own serialize-dos-r01/ directory, wired into the shared per-package pipeline
via run_pipeline_one_r06.py) is a 9th key, same discipline as REDOS_KEYS/PATH_TRAVERSAL_KEYS
below: always "enabled," never routed through staged_enablement.py's reachability-tier mechanism
(C/C++-specific). Safe regardless of gating: serialize_dos_r03.py's own `derive()` already
hardcodes every finding's own `"reportable": False` unconditionally (its own module docstring:
"pipeline integration is explicitly deferred"), same as ReDoS's/Path Traversal's own reducers --
this module's `f.get("reportable") is True` check can never count a Serialize DoS finding as
reportable no matter how "enabled" is set here.

ADDENDUM (ReDoS integration, roadmap step 8): `redos_findings` (redos_verdict.py, frozen, wired
into the shared per-package pipeline via run_pipeline_one_r06.py) is a 7th key, treated exactly
like RESOURCE_GUARD_KEYS/NAN_KEYS -- always "enabled," never routed through
staged_enablement.py's reachability-tier mechanism, which is specific to the five C/C++ staged
properties and has no bearing on ReDoS's own, separate JS-side reachability model
(PACKAGE_API_INPUT_REACHABLE / APPLICATION_INGRESS_REACHABLE, computed entirely inside
redos_verdict.py itself). This is safe regardless of gating: redos_verdict.py already hardcodes
every finding's own `"reportable": False` unconditionally (per direct instruction, until a real
npm package exercises the complete exported-input-to-regex path and survives manual review), so
this module's own `f.get("reportable") is True` check can never count a ReDoS finding as
reportable no matter how "enabled" is set here. provenance.py's reportable formula is
deliberately NOT extended to redos_findings by this change -- ReDoS keeps computing its own
reportable field exactly as it already does; out of scope here.
"""
DISABLED_PROPERTIES = {
    "oob_compare_candidates": (
        "task #33: a real positive-control fixture (oob_compare_controls.py, 10/10) proves the "
        "detector itself correctly recognizes its own target shape when built to trigger it "
        "(including the classic 'wrong sizeof' bug); a real corpus survey of 33 packages using "
        "memcmp/strncmp/CRYPTO_memcmp found zero real candidates and root-caused why (24 "
        "non-constant/variable extent, 15 string-literal operand, 7 sizeof() on something other "
        "than a bare compared-operand name, 2 other). The detector is real and sound; the bug "
        "shape it targets is genuinely rare in this corpus's own idiomatic C/C++. Deliberately "
        "kept non-reportable pending a real corpus positive or a wider run -- not an open "
        "precondition waiting to clear on its own, and not something this or a future "
        "aggregation step may silently re-enable."
    ),
}

# Resource Guard's own three lineage versions (task #41: R06 runs alongside R04/R05, never
# replacing either) -- their own reportable field comes from provenance.py's formula (task #35)
# plus whatever real applicability/adjudication evidence exists for them (task #41's own
# promote_via_js_linkage.py, when wired in, corrects source_boundary_evidence but does not
# itself flip applicability_status -- see check_provenance.py's own real node-libcurl
# diagnostic: applicability_status still defaults to NOT_YET_DETERMINED for a real R06 finding
# with no further evidence, so reportable stays False in practice until a real, separate,
# affirmative applicability step exists). staged_enablement.py deliberately never touches these
# three keys; this module trusts their own already-computed reportable field the same way.
RESOURCE_GUARD_KEYS = ("r04_findings", "r05_findings", "r06_findings")

# NAN CAPABILITY (frozen, study/nan_capability/NAN_CAPABILITY_FREEZE.md): a real, standalone
# Resource Guard variant for the Nan binding family, never sharing R04/R05/R06's own build-
# configuration applicability premise (that gate's whole premise does not hold for Nan's
# `.ToLocalChecked()` idiom -- see resource_guard_verdict_nan.py's own module docstring).
# Treated the same as RESOURCE_GUARD_KEYS here (always "enabled" -- never gated by
# staged_enablement.py, which only ever touches STAGED_KEYS below), kept in its own tuple since
# applicability_gate.py's own rule for it is real and distinct, not merely R04/R05/R06 reused.
NAN_KEYS = ("nan_findings",)

# REDOS (roadmap step 8): a real, standalone JS/TS-side property, wired into the shared
# per-package pipeline via run_pipeline_one_r06.py (never sharing R04/R05/R06/Nan's own C/C++
# build-configuration or Nan-idiom applicability premises, and never routed through
# staged_enablement.py's reachability-tier mechanism -- see module docstring ADDENDUM above).
# Kept in its own tuple, same discipline as NAN_KEYS: always "enabled" here, but a distinct real
# rule from RESOURCE_GUARD_KEYS/NAN_KEYS, not merely reused.
REDOS_KEYS = ("redos_findings",)

# PATH TRAVERSAL (roadmap step 8, second JS/TS class): same discipline as REDOS_KEYS -- a real,
# standalone JS/TS-side property, wired into the shared per-package pipeline via
# run_pipeline_one_r06.py, never routed through staged_enablement.py's reachability-tier mechanism
# (that mechanism is C/C++-specific). Always "enabled" here; safe regardless, since
# path_traversal_verdict.py already hardcodes every finding's own "reportable": False
# unconditionally, same as ReDoS's own reducer.
PATH_TRAVERSAL_KEYS = ("path_traversal_findings",)

# SERIALIZE DOS (roadmap step 8, third of 4 JS/TS classes): same discipline as REDOS_KEYS/
# PATH_TRAVERSAL_KEYS -- a real, standalone JS/TS-side property, wired into the shared
# per-package pipeline via run_pipeline_one_r06.py, never routed through staged_enablement.py's
# reachability-tier mechanism (C/C++-specific). Always "enabled" here; safe regardless, since
# serialize_dos_r03.py's own derive() already hardcodes every finding's own "reportable": False
# unconditionally, same as ReDoS's/Path Traversal's own reducers.
SERIALIZE_DOS_KEYS = ("serialize_dos_findings",)

STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
               "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates")

ALL_PROPERTY_KEYS = (RESOURCE_GUARD_KEYS + NAN_KEYS + REDOS_KEYS + PATH_TRAVERSAL_KEYS
                      + SERIALIZE_DOS_KEYS + STAGED_KEYS)


def aggregate_record(record, enabled_properties):
    """Summarizes one already-fully-processed record (see module docstring for the required
    upstream pipeline order) across all real finding/candidate keys (`ALL_PROPERTY_KEYS`).
    `enabled_properties` is
    passed in explicitly (the caller's own `staged_enablement.ENABLED_PROPERTIES`, or an
    equivalent real set) rather than imported and used implicitly, so a caller auditing this
    module's own behavior can see exactly what enablement state produced a given summary,
    and so a test can exercise this function against a deliberately-different set without
    monkeypatching a module-level import.

    Returns {property_key: {"raw_count", "reportable_count", "enabled", "disabled_reason"}},
    plus "_totals": {"total_raw", "total_reportable"}. Raises AssertionError if a DISABLED
    property (per DISABLED_PROPERTIES) is found to have contributed ANY reportable finding --
    a real, hard invariant violation, never silently absorbed into the totals."""
    summary = {}
    for key in ALL_PROPERTY_KEYS:
        items = record.get(key) or []
        reportable_count = sum(1 for f in items if f.get("reportable") is True)
        if (key in RESOURCE_GUARD_KEYS or key in NAN_KEYS or key in REDOS_KEYS
                or key in PATH_TRAVERSAL_KEYS or key in SERIALIZE_DOS_KEYS):
            enabled, reason = True, None
        elif key in DISABLED_PROPERTIES:
            enabled, reason = False, DISABLED_PROPERTIES[key]
            if reportable_count:
                raise AssertionError(
                    f"INVARIANT VIOLATION: {key} is a DISABLED property (reason: {reason!r}) "
                    f"but has {reportable_count} real reportable finding(s) in this record -- "
                    "this must never happen; staged_enablement.py's own gate did not correctly "
                    "force it non-reportable, or this record was not actually run through it.")
        else:
            enabled = key in enabled_properties
            reason = None if enabled else "not yet enabled (no disclosed reason on record)"
        summary[key] = {"raw_count": len(items), "reportable_count": reportable_count,
                         "enabled": enabled, "disabled_reason": reason}
    summary["_totals"] = {
        "total_raw": sum(e["raw_count"] for k, e in summary.items() if k != "_totals"),
        "total_reportable": sum(e["reportable_count"] for k, e in summary.items()
                                 if k != "_totals"),
    }
    return summary


def format_summary(summary):
    """Real, human-readable rendering of aggregate_record()'s own output -- for a smoke test's
    own printed output or a future report, never a second source of truth (every number here is
    read directly from the summary dict, nothing recomputed)."""
    lines = []
    for key in ALL_PROPERTY_KEYS:
        e = summary[key]
        tag = "ENABLED " if e["enabled"] else "DISABLED"
        reason = f" -- {e['disabled_reason']}" if e["disabled_reason"] else ""
        lines.append(f"  [{tag}] {key}: raw={e['raw_count']} reportable={e['reportable_count']}"
                      f"{reason}")
    t = summary["_totals"]
    lines.append(f"  TOTAL: raw={t['total_raw']} reportable={t['total_reportable']}")
    return "\n".join(lines)
