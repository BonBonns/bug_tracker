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
a verdict shape). Matching is EXACT -- a site that merely looks similar is never matched. Adding
an entry here means someone did the real review this module's own docstring cites; this module
never does that review itself. Two separate tables, since Resource Guard (R04/R05/R06) and the
staged properties (LOCK_BALANCE/PROTECTED_FIELD/OOB_*) key their own findings by different real
identity fields:
  KNOWN_ADJUDICATIONS         -- Resource Guard, keyed by (package_name, version, method_name,
                                  source_path).
  KNOWN_STAGED_ADJUDICATIONS  -- staged properties, keyed by (package_name, version,
                                  staged_property_key, site_identity) -- site_identity is
                                  `site_id` for the OOB_* producers (already a real, unique,
                                  per-call-site field: `"<function>:<line>:<call>"`) or
                                  `lock_call_id` for LOCK_BALANCE/PROTECTED_FIELD (the real,
                                  unique Joern node id of the specific lock/access call) --
                                  never `method_id` alone, which can be shared by more than one
                                  real finding at the same function (e.g. bluetooth-hci-socket's
                                  own real `bindRaw` carries 2 distinct OOB_WRITE candidates,
                                  one per real call site, at the same function_id).

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


# Real, individually-reviewed, cited adjudications for the STAGED properties (LOCK_BALANCE/
# PROTECTED_FIELD/OOB_*) -- see study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md for
# the full, real account of all 5 entries below (task #32's own reopened transitive-call tier's
# first 5 real promotions, manually validated per direct instruction BEFORE any further
# scanning). Keyed by (package_name, version, staged_key, site_identity) -- see this module's
# own docstring for why site_identity is `site_id` (OOB_*) or `lock_call_id` (LOCK_BALANCE/
# PROTECTED_FIELD), never `method_id` alone.
KNOWN_STAGED_ADJUDICATIONS = {
    ("@abandonware/bluetooth-hci-socket", "0.5.3-12", "oob_write_candidates", "bindRaw:279:memset"): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md",
        "reason": ("memset(_address, 0, sizeof(_address)) -- _address is uint8_t _address[6] "
                   "(BluetoothHciSocket.h:111); sizeof(_address) on an array is purely "
                   "self-referential and correctly evaluates to 6, matching dest_capacity_bytes "
                   "exactly. Cannot overflow."),
    },
    ("@abandonware/bluetooth-hci-socket", "0.5.3-12", "oob_write_candidates", "bindRaw:284:memcpy"): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md",
        "reason": ("memcpy(_address, &di.bdaddr, sizeof(di.bdaddr)) -- di.bdaddr is bdaddr_t "
                   "(struct hci_dev_info, real Linux BlueZ type), always exactly 6 real bytes "
                   "(a Bluetooth device address); _address is uint8_t _address[6]. A different-"
                   "variable sizeof() the extent-derivation logic could not statically confirm, "
                   "but the real numeric sizes, read directly from both type declarations, "
                   "match exactly. Not a vulnerability."),
    },
    ("@confluentinc/kafka-javascript", "1.10.0", "lock_balance_findings", 30065064094): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md",
        "reason": ("mtx_lock (tinycthread.c:110) is the real threading-primitive wrapper "
                   "itself -- its own body only acquires and returns, by design; release is a "
                   "SEPARATE function (mtx_unlock) or the caller's own job. The real caller on "
                   "this exact path (rd_refcnt_sub0, rd.h:353) correctly calls BOTH mtx_lock "
                   "AND mtx_unlock, directly adjacent -- genuinely balanced. LOCK_BALANCE's own "
                   "'does this function also release' question is structurally the wrong "
                   "question to ask of the primitive-defining function itself."),
    },
    ("@confluentinc/kafka-javascript", "1.10.0", "lock_balance_findings", 30065064366): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md",
        "reason": ("rwlock_rdlock (tinycthread_extra.c) -- the same real primitive-wrapper "
                   "shape as mtx_lock above: acquires and returns by design, release is a "
                   "separate function/the caller's own job."),
    },
    ("@eliyya/sange", "1.2.0", "lock_balance_findings", 30064773906): {
        "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
        "citation": "study/task34_replay/TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md",
        "reason": ("Mutex::lock() (src/thread.h:11): 'int lock(){ return "
                   "pthread_mutex_lock(&mutex); }' -- a one-line primitive wrapper; unlock() is "
                   "a separate sibling method 3 lines later (src/thread.h:15). The same real "
                   "primitive-wrapper shape as kafka-javascript's own mtx_lock/rwlock_rdlock, "
                   "confirmed independently on a second, unrelated real codebase."),
    },
}

_STAGED_SITE_ID_FIELD = {
    "lock_balance_findings": "lock_call_id",
    "protected_field_findings": "lock_call_id",
    "oob_write_candidates": "site_id",
    "oob_index_write_candidates": "site_id",
    "oob_read_candidates": "site_id",
    "oob_compare_candidates": "site_id",
}


def apply_known_adjudications(record):
    """Applied AFTER provenance.enrich_record() (needs each finding's own resolved source_path)
    -- for every real finding/candidate key this record carries, checks for an EXACT match
    against KNOWN_ADJUDICATIONS (Resource Guard: package_name+version+method_name+source_path)
    or KNOWN_STAGED_ADJUDICATIONS (staged properties: package_name+version+staged_key+
    site_identity); on a match, sets adjudication_status + a real citation/reason, then
    RECOMPUTES reportable via provenance.finalize_reportability() (never leaves a stale
    reportable computed from the pre-adjudication default) so the veto takes effect immediately,
    not on some later pass. Silently no-ops for every finding that doesn't exactly match --
    never a partial/fuzzy match, never guessed from a package name or verdict shape alone."""
    import provenance as _provenance  # local import: avoids a hard circular-import dependency
                                       # for callers that only need the registry table itself.

    pkg = record.get("package_name")
    ver = record.get("version")
    applied = 0
    # nan_findings shares this SAME table/loop -- resource_guard_verdict_nan.py's own findings
    # carry the same real (method_name, source_path) site-identity shape as R04/R05/R06's own
    # (see its base_evidence construction), and a real site a human has individually adjudicated
    # is the same real site regardless of which scanner variant (node-addon-api vs. Nan lineage)
    # flagged it -- matching this table's own already-established, lineage-agnostic precedent for
    # R04/R05/R06 sharing one table (see this function's own docstring/module docstring).
    for key in ("r04_findings", "r05_findings", "r06_findings", "nan_findings"):
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
    for key, id_field in _STAGED_SITE_ID_FIELD.items():
        for f in record.get(key) or []:
            site_identity = f.get(id_field)
            entry = KNOWN_STAGED_ADJUDICATIONS.get((pkg, ver, key, site_identity))
            if entry is None:
                continue
            f["adjudication_status"] = entry["adjudication_status"]
            f["adjudication_citation"] = entry["citation"]
            f["adjudication_reason"] = entry["reason"]
            is_candidate = f.get("scanner_candidate", False)
            _provenance.finalize_reportability(f, is_candidate)
            applied += 1
    return applied
