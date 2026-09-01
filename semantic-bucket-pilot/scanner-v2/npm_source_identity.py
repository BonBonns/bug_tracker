#!/usr/bin/env python3
"""NPM-SOURCE-IDENTITY-R01 (task #52): property-neutral shared "npm source identity" Python
module -- the reducer-side counterpart of
tchecker-research-complete/tchecker-property-adjudicator/producers/export_npm_source_identity.sc.

Importable by any future property reducer (path-traversal, serialize-DoS, or anything else) that
wants canonical source paths, content hashes, package-owned/vendored attribution, and
cross-package vendored deduplication for a JS/TS package's own findings -- WITHOUT re-deriving any
of that logic itself. This module never invents a NEW dedup-key scheme or a NEW hashing scheme; it
is a thin, JS-shaped adapter over the two existing, real modules already proven for the C/C++ side:

  - `provenance.py`'s `sha256_hex` / `compute_source_tree_sha256` / `classify_vendored_hint` /
    `build_source_manifest` -- imported and reused verbatim, never reimplemented (this repo
    already has one accidental duplication of the source-tree-hash idea, in
    `npm_corpus/dedup_eligible.py`'s own `tree_hash` -- this module deliberately does not add a
    third).
  - `vendored_attribution.py`'s `attribute_finding` / `aggregate_vendored_dedup` -- called
    directly against JS-finding dicts shaped to satisfy exactly what those two functions read
    (confirmed by reading their real source: `attribute_finding` needs only
    `finding["provenance"]["resolved"]` / `["provenance_hint"]` / `["source_path"]` /
    `["content_hash"]`, plus one of its own recognized site-signature keys --
    `call`/`index_expr`/`field_code`/`method_name`/`reason` -- to keep two DIFFERENT real sites on
    the same line from colliding into one dedup bucket; this module supplies `reason` with the
    origin_family + site_code, so the SAME real function is reused with ZERO changes).
    `aggregate_vendored_dedup` alone needed one small, additive, backward-compatible change (an
    optional `keys=None` parameter, defaulting to the untouched `ALL_FINDING_KEYS` for every
    existing C/C++ caller) because it was otherwise hard-coded to only ever scan the nine
    C/C++-only finding-list keys named in `ALL_FINDING_KEYS` -- see vendored_attribution.py's own
    updated docstring on that function for the exact change and why.

Reads export_npm_source_identity.sc's own three raw TSVs directly (source_origin_facts.tsv,
export_surface.tsv, closure_identity.tsv), the same "producer emits a flat TSV, consumer
groups/reads it directly" convention already established by redos_verdict.py's own
`families_by_sink` (never a single-origin summary field).
"""
import os

import provenance
import vendored_attribution

# Re-exported verbatim so a caller need only import THIS module -- never reimplemented here.
sha256_hex = provenance.sha256_hex
compute_source_tree_sha256 = provenance.compute_source_tree_sha256
classify_vendored_hint = provenance.classify_vendored_hint

NPM_SOURCE_IDENTITY_FINDING_KEY = "npm_source_identity_findings"

_ORIGIN_FACTS_COLS = 8
_EXPORT_SURFACE_COLS = 10
_CLOSURE_IDENTITY_COLS = 11


def _read_tsv(path, n):
    """Same discipline as redos_verdict.py's own `_read_tsv`: silently skip a short/malformed
    line rather than crash on one, never silently accept a row with the wrong column count."""
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip("\n"):
                continue
            parts = ln.rstrip("\n").split("\t")
            if len(parts) == n:
                out.append(parts)
    return out


# ============================== source_origin_facts.tsv reading ==============================

def read_source_origin_facts(raw_dir):
    """Returns the raw rows of source_origin_facts.tsv as dicts, one per (site, origin_family)
    row -- NEVER collapsed, matching the producer's own "never collapse a multi-origin site"
    guarantee. Columns: site_id, file, line, site_code, origin_family, family_detail,
    multi_origin, origin_count."""
    rows = _read_tsv(os.path.join(raw_dir, "source_origin_facts.tsv"), _ORIGIN_FACTS_COLS)
    out = []
    for r in rows:
        out.append({
            "site_id": r[0], "file": r[1], "line": r[2], "site_code": r[3],
            "origin_family": r[4], "family_detail": r[5],
            "multi_origin": r[6] == "true", "origin_count": int(r[7]) if r[7].isdigit() else 0,
        })
    return out


def families_by_site(raw_dir):
    """site_id -> set of origin_family values reaching it -- the SAME "read the flat TSV
    directly, group by hand" convention as redos_verdict.py's own `families_by_sink` (never a
    single-origin summary field). A site with more than one family here is a real,
    non-collapsed MULTIPLE_ORIGINS site."""
    out = {}
    for row in read_source_origin_facts(raw_dir):
        out.setdefault(row["site_id"], set()).add(row["origin_family"])
    return out


# ============================== export_surface.tsv / closure_identity.tsv reading ==============

def read_export_surface(raw_dir):
    """export_id, file, line, export_lhs, export_name, rhs_kind, resolution_status,
    target_method_id, target_method_full_name, abstain_reason."""
    rows = _read_tsv(os.path.join(raw_dir, "export_surface.tsv"), _EXPORT_SURFACE_COLS)
    cols = ("export_id", "file", "line", "export_lhs", "export_name", "rhs_kind",
            "resolution_status", "target_method_id", "target_method_full_name", "abstain_reason")
    return [dict(zip(cols, r)) for r in rows]


def read_closure_identity(raw_dir):
    """identifier_id, file, line, method_full_name, identifier_code, resolution_kind,
    resolved_root_id, resolved_root_name, resolved_root_kind, capture_depth, note."""
    rows = _read_tsv(os.path.join(raw_dir, "closure_identity.tsv"), _CLOSURE_IDENTITY_COLS)
    cols = ("identifier_id", "file", "line", "method_full_name", "identifier_code",
            "resolution_kind", "resolved_root_id", "resolved_root_name", "resolved_root_kind",
            "capture_depth", "note")
    return [dict(zip(cols, r)) for r in rows]


# ============================== per-package source manifest (capability 5) =====================

def build_js_source_manifest(pkg_dir, package_name, version, tarball_bytes=b""):
    """Thin wrapper over provenance.build_source_manifest -- walks the already-extracted JS/TS
    package tree at pkg_dir and returns {schema, package_name, version, tarball_sha256,
    source_tree_sha256, files: {relpath: {content_hash, provenance_hint}}}. `tarball_bytes` is
    optional (pass real tarball bytes when available -- e.g. straight from one of the
    fixtures/npm_source_identity_r01/dev_packages/*.tgz files -- for a real tarball_sha256;
    omitting it still gives a real, reproducible source_tree_sha256, which is the canonical,
    tarball-independent hash this module actually needs for capability 5/7)."""
    return provenance.build_source_manifest(pkg_dir, tarball_bytes, package_name, version)


def _normalize_relpath(raw_file_field, strip_prefix=None):
    """export_npm_source_identity.sc emits REAL Joern `.filename` paths, relative to whatever
    root directory jssrc2cpg was pointed at. When that root held several packages side by side
    (this module's own real regression evidence: motifer/logify/miniml/ms built as ONE combined
    CPG, see check_npm_source_identity.py), each package's own files carry a
    "<package_dir_name>/..." prefix that a manifest built by walking just that ONE package's own
    pkg_dir will not have -- `strip_prefix` (the package's own directory name used inside that
    combined root) removes exactly that, and only that, prefix. Never guesses a prefix; a caller
    building one CPG per package should simply omit `strip_prefix` (default: None, no stripping)."""
    f = raw_file_field.lstrip("./")
    if strip_prefix:
        prefix = strip_prefix.strip("/") + "/"
        if f.startswith(prefix):
            f = f[len(prefix):]
    return f


def lookup_source_fact(raw_file_field, manifest, strip_prefix=None):
    """Joins one raw-output row's own `file` field to the manifest built by
    build_js_source_manifest, returning {resolved, source_path, content_hash, provenance_hint} --
    the SAME fail-closed discipline as provenance.py's own `enrich_finding` (an unresolved path or
    an unreadable-at-scan-time file both come back resolved=False with a real, disclosed reason;
    never guessed, never silently dropped)."""
    relpath = _normalize_relpath(raw_file_field, strip_prefix)
    entry = manifest.get("files", {}).get(relpath)
    if entry is None:
        return {"resolved": False, "source_path": relpath, "content_hash": None,
                "provenance_hint": "PATH_NOT_IN_MANIFEST"}
    if entry.get("content_hash") is None:
        return {"resolved": False, "source_path": relpath, "content_hash": None,
                "provenance_hint": entry.get("provenance_hint")}
    return {"resolved": True, "source_path": relpath, "content_hash": entry["content_hash"],
            "provenance_hint": entry["provenance_hint"]}


# ============================== attribution + cross-package dedup (capabilities 6/7) ===========

def make_finding(package_name, site_id, origin_family, source_fact, file=None, line=None,
                  site_code=None, extra=None):
    """Builds ONE finding dict shaped exactly as `vendored_attribution.attribute_finding` and
    `aggregate_vendored_dedup` read: a `provenance` sub-dict (resolved/provenance_hint/
    source_path/content_hash) plus a `reason` field (one of `attribute_finding`'s own recognized
    site-signature keys -- see this module's own top-level docstring) carrying real,
    site-distinguishing text so two DIFFERENT real sites on the same line are never accidentally
    collapsed into the same dedup bucket. `package_name` is carried on the finding itself too
    (not required by vendored_attribution, but convenient for a caller building records directly
    from a flat findings list rather than grouping by package first -- see
    `attribute_and_dedup_by_package` below, which does that grouping either way)."""
    finding = {
        "package_name": package_name,
        "site_id": site_id,
        "origin_family": origin_family,
        "file": file,
        "line": line,
        "site_code": site_code,
        "reason": f"{origin_family}:{site_code}",
        "provenance": {
            "resolved": source_fact["resolved"],
            "provenance_hint": source_fact["provenance_hint"],
            "source_path": source_fact["source_path"],
            "content_hash": source_fact["content_hash"],
        },
    }
    if extra:
        finding.update(extra)
    return finding


def attribute_and_dedup_by_package(findings_by_package,
                                    key=NPM_SOURCE_IDENTITY_FINDING_KEY):
    """Capabilities 6 (package-owned vs vendored) + 7 (vendored dedup, retaining every exposing
    package): `findings_by_package` is {package_name: [finding, ...]} (each finding shaped by
    `make_finding`). Runs `vendored_attribution.attribute_finding` on every finding in place (a
    PACKAGE_OWNED_HINT or unresolved finding is left untouched -- attribution is additive and
    conditional there, never a default; see that function's own docstring), then
    `vendored_attribution.aggregate_vendored_dedup` (passing `keys=(key,)`, the one small,
    additive parameter this task added to that function -- see its own updated docstring) to
    collapse byte-identical vendored files bundled by more than one package into ONE
    deduplicated entry that still lists EVERY package exposing it (never drops one). Returns
    (records, aggregated) -- `records` are the same finding lists, now attribution-annotated in
    place; `aggregated` is vendored_attribution's own real {key: {dedup_key: {...,
    "packages": [...]}}} shape."""
    records = []
    for pkg, findings in findings_by_package.items():
        for f in findings:
            vendored_attribution.attribute_finding(f, pkg)
        records.append({"package_name": pkg, key: findings})
    aggregated = vendored_attribution.aggregate_vendored_dedup(records, keys=(key,))
    return records, aggregated


def summarize(aggregated, key=NPM_SOURCE_IDENTITY_FINDING_KEY):
    """{"deduplicated_count": N, "raw_exposure_count": M} for this module's own finding key --
    the same two headline numbers vendored_attribution.summarize() already reports for the
    C/C++ properties, computed the identical way (never collapsed into one number)."""
    buckets = aggregated.get(key, {})
    return {
        "deduplicated_count": len(buckets),
        "raw_exposure_count": sum(b["raw_exposure_count"] for b in buckets.values()),
    }
