#!/usr/bin/env python3
"""VENDOR-ATTR-R01 (task #31): real vendored-vs-package-owned classification and cross-package
deduplication -- built on, not replacing, provenance.py's own `classify_vendored_hint()`
(explicitly documented there as a "best-effort, cheap, path-only heuristic... task #31 owns the
real classification").

WHY THIS EXISTS: a finding inside vendored third-party source (e.g. `re2`'s bundled
`abseil-cpp`) must never be silently counted as an unqualified finding against the npm package
under study -- but it must not be silently discarded either. A reachable vendored bug is a real
bug; it needs attribution (upstream library, not the bundling package) and deduplication (the
SAME vendored file, bundled byte-identically by several different npm packages, must not be
counted as N unrelated findings).

REAL LIBRARY IDENTITY, not guessed: for a finding whose `provenance.provenance_hint ==
'VENDORED_HINT'`, the vendored library's own identity is the path segment immediately following
whichever `provenance.VENDOR_PATH_MARKERS` entry matched -- e.g. `vendor/abseil-cpp/absl/base/
internal/strerror.cc` -> `abseil-cpp`; `deps/openssl/ssl/ssl_lib.c` -> `openssl`. Confirmed
directly against real evidence from the overnight-diagnostic-100 run: `re2`'s own real
`oob_write_candidates` finding at `vendor/abseil-cpp/absl/base/internal/strerror.cc` extracts
correctly to `abseil-cpp`. Reuses `provenance.VENDOR_PATH_MARKERS` verbatim -- never a separate,
divergent marker list.

REAL DEDUPLICATION KEY, evidence-backed: `(vendored_library_id, relpath_within_vendor_dir,
content_hash, line, call_or_index_signature)`. Using the finding's own already-real
`provenance.content_hash` (not just relpath+line) is the reason two packages bundling the exact
SAME vendored file (byte-identical) correctly collapse to one deduplicated entry, while two
packages bundling DIFFERENT VERSIONS of the same library at the same relpath (different bytes,
different content_hash) correctly do NOT collapse -- a version difference can mean the
vulnerable line doesn't even exist in the other version, so collapsing on relpath alone would be
unsound. `relpath_within_vendor_dir` (the path AFTER the library's own root directory) is used
rather than the finding's raw absolute-within-package relpath, so the SAME vendored file at a
DIFFERENT nesting depth in a different package's tree (e.g. `vendor/abseil-cpp/...` vs
`third_party/abseil-cpp/...`) still dedups correctly -- the vendor ROOT differs, the file's own
path INSIDE that root does not.

ATTRIBUTION STRING, per direct instruction: "<upstream library> as bundled by <npm package>" --
never an unqualified package finding. Computed per (finding, package) pair, since the same
deduplicated vendored bug is independently "bundled by" every package that carries it.

Deliberately does NOT decide reportability -- this module only attributes and deduplicates
what's already there; provenance.py's own reportable formula (task #35) is unaffected and stays
the sole authority on that question.
"""
import re

import provenance as _provenance

VENDOR_PATH_MARKERS = _provenance.VENDOR_PATH_MARKERS  # reused verbatim, never redefined


def extract_vendored_library_id(relpath):
    """Returns (library_id, relpath_within_vendor_dir) for a real VENDORED_HINT source_path, or
    (None, None) if no vendor marker matches (should not happen for a finding whose
    provenance_hint is already VENDORED_HINT, computed from the SAME marker list -- defensive,
    not assumed). The library id is the path segment immediately after whichever marker matched;
    if that segment is itself empty (a malformed/edge-case path), returns (None, None) rather
    than guessing."""
    if not relpath:
        return None, None
    norm = relpath.replace("\\", "/")
    norm_lower = norm.lower()
    for marker in VENDOR_PATH_MARKERS:
        marker_norm = marker.replace("\\", "/").lower()
        idx = norm_lower.find(marker_norm)
        if idx == -1:
            continue
        after = norm[idx + len(marker_norm):]
        parts = after.split("/", 1)
        lib_id = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        if not lib_id:
            return None, None
        return lib_id, rest
    return None, None


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def _finding_site_signature(finding):
    """A stable, real signature for the finding's own site WITHIN its file -- line plus whatever
    call/index-expression identity the finding already carries (never invented): 'call' for the
    OOB producers, 'index_expr' for indexed writes, 'field_code'/'method_name' for
    LOCK_BALANCE/PROTECTED_FIELD. Falls back to the finding's own 'reason'/'derivation' text if
    none of those are present, rather than silently using line alone (two distinct real bugs on
    the same line, e.g. two calls in one macro-expanded statement, must not collapse)."""
    line = finding.get("line")
    for key in ("call", "index_expr", "field_code", "method_name", "reason"):
        if finding.get(key):
            return (line, key, finding[key])
    return (line, "derivation", str(finding.get("derivation")))


def attribute_finding(finding, package_name):
    """Attaches vendored-attribution fields to ONE finding, in place, IFF its own
    provenance.provenance_hint is VENDORED_HINT and its provenance actually resolved (an
    unresolved finding has no real source_path to attribute from at all). Never touches a
    PACKAGE_OWNED_HINT or UNKNOWN finding -- attribution is additive and conditional, not a
    default. Returns the finding either way."""
    prov = finding.get("provenance") or {}
    if not prov.get("resolved") or prov.get("provenance_hint") != "VENDORED_HINT":
        return finding
    lib_id, rest = extract_vendored_library_id(prov.get("source_path"))
    if lib_id is None:
        finding["vendored_attribution"] = {
            "status": "MARKER_MATCHED_BUT_LIBRARY_ID_UNRESOLVED",
            "vendored_library_id": None,
        }
        return finding
    finding["vendored_attribution"] = {
        "status": "ATTRIBUTED",
        "vendored_library_id": lib_id,
        "relpath_within_vendor_dir": rest,
        "attribution": f"{lib_id} as bundled by {package_name}",
        "dedup_key": (lib_id, rest, prov.get("content_hash")) + _finding_site_signature(finding),
    }
    return finding


ALL_FINDING_KEYS = ("r04_findings", "r05_findings", "lock_balance_findings",
                     "protected_field_findings", "oob_write_candidates",
                     "oob_index_write_candidates", "oob_read_candidates",
                     "oob_compare_candidates")


def attribute_record(record):
    """Runs attribute_finding() over every real finding/candidate key present in one pipeline
    record, in place. Safe to call regardless of which properties actually ran (silently skips
    an absent key, same discipline as provenance.enrich_record)."""
    pkg = record.get("package_name")
    for key in ALL_FINDING_KEYS:
        for f in record.get(key) or []:
            attribute_finding(f, pkg)
    return record


def aggregate_vendored_dedup(records):
    """Cross-package deduplication across a whole run's worth of records (already
    attribute_record()-processed, or processed here on the fly). Returns
    {property_key: {dedup_key: {"vendored_library_id", "relpath_within_vendor_dir",
    "raw_exposure_count", "deduplicated": True, "packages": [sorted, unique package names],
    "sample_attribution": str}}} -- the deduplicated_count for a property is simply
    len(that property's dict); raw_exposure_count per entry is how many (package, finding) pairs
    mapped to it, i.e. the real corpus exposure before deduplication."""
    out = {k: {} for k in ALL_FINDING_KEYS}
    for record in records:
        pkg = record.get("package_name")
        for key in ALL_FINDING_KEYS:
            for f in record.get(key) or []:
                va = f.get("vendored_attribution")
                if not va or va.get("status") != "ATTRIBUTED":
                    attribute_finding(f, pkg)
                    va = f.get("vendored_attribution")
                if not va or va.get("status") != "ATTRIBUTED":
                    continue
                dk = tuple(va["dedup_key"])
                bucket = out[key].setdefault(dk, {
                    "vendored_library_id": va["vendored_library_id"],
                    "relpath_within_vendor_dir": va["relpath_within_vendor_dir"],
                    "raw_exposure_count": 0,
                    "packages": set(),
                    "sample_attribution": va["attribution"],
                })
                bucket["raw_exposure_count"] += 1
                bucket["packages"].add(pkg)
    for key in out:
        for dk, bucket in out[key].items():
            bucket["packages"] = sorted(bucket["packages"])
            bucket["deduplicated"] = True
    return out


def summarize(agg):
    """{property_key: {"deduplicated_count": N, "raw_exposure_count": M}} -- the two headline
    numbers task #31 requires reporting side by side, never collapsed into one."""
    out = {}
    for key, buckets in agg.items():
        out[key] = {
            "deduplicated_count": len(buckets),
            "raw_exposure_count": sum(b["raw_exposure_count"] for b in buckets.values()),
        }
    return out
