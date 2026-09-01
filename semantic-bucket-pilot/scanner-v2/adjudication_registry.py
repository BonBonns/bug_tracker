#!/usr/bin/env python3
"""ADJUDICATION-REGISTRY-R01: the real, missing affirmative-adjudication step task #41's own
docstring already disclosed as absent ("no real, separate, affirmative applicability step
exists"). `provenance.finalize_reportability()`'s own `adjudication_status` field has existed
since task #35, is read by the reportable formula's own veto clause
(`adjudication_status != "CONFIRMED_FALSE_POSITIVE"`), and defaults to `"NOT_ADJUDICATED"` --
but until this module, NOTHING in the pipeline ever affirmatively set it to
`"CONFIRMED_FALSE_POSITIVE"` for a real corpus finding, even for node-libcurl's own
Easy::ReadFunction, whose false-positive status is the SAME real, independently-verified finding
`resource_guard_verdict_r06.py` (R06) itself exists because of, and which
`study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` documents in full, real,
two-independent-reasons detail (grep confirmed: not one other file in this pipeline ever assigns
`adjudication_status = "CONFIRMED_FALSE_POSITIVE"`).

DISCIPLINE, matching every other real-evidence module in this pipeline: this registry contains
ONLY sites that have ALREADY been manually, individually reviewed and documented with a real,
citable account (never a heuristic, never a pattern match, never inferred from a package name or
a verdict shape). Matching is EXACT (package_name + version + method_name + source_path, all
four) -- a site that merely looks similar is never matched. Adding an entry here means someone
did the real review this module's own docstring cites; this module never does that review
itself.

WHY THIS IS SEPARATE FROM resource_guard_verdict_r06.py'S OWN SOURCE-BOUNDARY GATE: R06's
`source_boundary_evidence`/`SOURCE_BOUNDARY_UNRESOLVED` answers "does THIS specific structural
trace establish attacker influence" -- a general, corpus-wide analyzer question, answered the
same way for every finding, never citing one specific package's own manual review. This module
answers "has a HUMAN ALREADY manually confirmed this EXACT site is a false positive" -- a
narrower, per-site, evidence-backed historical record, never a substitute for R06's own general
fix (R06 still correctly reports SOURCE_BOUNDARY_UNRESOLVED for node-libcurl's own finding
independent of this registry; this registry additionally records the affirmative human
adjudication that already happened, on top of that).
"""

# Real, individually-reviewed, cited adjudications. Keyed by the exact tuple this module matches
# on (package_name, version, method_name, source_path) -- see apply_known_adjudications() below.
# Each entry's own `citation` names the real document containing the full account; `reason` is a
# short, real summary, never a substitute for reading the citation.
KNOWN_ADJUDICATIONS = {
    ("node-libcurl", "5.1.2", "ReadFunction", "src/Easy.cc"): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md",
        "reason": (
            "Two independent, compounding reasons, both real and verified against the exact "
            "published tarball (never assumed): (1) `size`/`nmemb` are NOT attacker/JS-"
            "controlled -- Easy::ReadFunction is a libcurl-invoked callback "
            "(`curl_easy_setopt(ch, CURLOPT_READFUNCTION, Easy::ReadFunction)`), never called "
            "by JS; libcurl itself supplies these parameters per CURLOPT_READFUNCTION's own "
            "documented contract, confirmed structurally in the real code -- this is the same "
            "real defect R06's own source-boundary gate was built to correct generally, "
            "confirmed here on the exact site that motivated it. (2) The contract's own real "
            "applicability precondition does NOT hold the way this pipeline's static contract-"
            "matching assumes: exceptions ARE enabled for this build (node-addon-api's "
            "node_addon_api_except gyp target, traced through the real node-addon-api 8.5.0 "
            "macro chain), and a real, working guard already exists via a C++ try/catch "
            "(Napi::Error) around the allocation -- a real guard, just not the "
            ".IsEmpty()/null-Data() shape this pipeline's own contract matching looks for."
        ),
    },
}


def apply_known_adjudications(record):
    """Applied AFTER provenance.enrich_record() (needs each finding's own resolved source_path)
    -- for every real finding/candidate key this record carries, checks for an EXACT
    (package_name, version, method_name, source_path) match against KNOWN_ADJUDICATIONS; on a
    match, sets adjudication_status + a real citation/reason, then RECOMPUTES reportable via
    provenance.finalize_reportability() (never leaves a stale reportable computed from the
    pre-adjudication default) so the veto takes effect immediately, not on some later pass.
    Silently no-ops for every finding that doesn't exactly match -- never a partial/fuzzy match,
    never guessed from a package name or verdict shape alone."""
    import provenance as _provenance  # local import: avoids a hard circular-import dependency
                                       # for callers that only need the registry table itself.

    pkg = record.get("package_name")
    ver = record.get("version")
    applied = 0
    for key in ("r04_findings", "r05_findings", "r06_findings"):
        for f in record.get(key) or []:
            method_name = f.get("method_name")
            source_path = (f.get("provenance") or {}).get("source_path")
            entry = KNOWN_ADJUDICATIONS.get((pkg, ver, method_name, source_path))
            if entry is None:
                continue
            f["adjudication_status"] = entry["adjudication_status"]
            f["adjudication_citation"] = entry["citation"]
            f["adjudication_reason"] = entry["reason"]
            is_candidate = f.get("scanner_candidate", False)
            _provenance.finalize_reportability(f, is_candidate)
            applied += 1
    return applied
