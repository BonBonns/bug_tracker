#!/usr/bin/env python3
"""PROV-R01 (task #35): pipeline-wide source-path + content-hash preservation.

Direct instruction, corrected across several rounds to its final scope: this is a PIPELINE-WIDE
precondition, not a dependency of any one property's own staged-enablement gate. It applies to
all six properties -- FALLIBLE_BOUNDED_RESOURCE (R04/R05) included, not only the five properties
task #28 newly integrated -- because the pilot itself established that NONE of the six properties'
current finding schemas carry a source file path or a content hash at all, and
run_pipeline_one.py's own disk-bounding discipline deletes the extracted source tree after every
package regardless of outcome. Provenance CLASSIFICATION (package-owned vs. vendored, task #31)
may happen later; the raw evidence it needs cannot be recreated once that deletion happens, so it
must be captured here, at scan time, before any scanner runs.

Captures exactly the six fields specified by direct instruction:
  1. package name and pinned version
  2. a source-tree hash (sha256 of the ORIGINAL tarball bytes -- the single canonical artifact
     the extracted tree came from, deterministic, no filesystem-walk-order dependency)
  3. the exact relative source path of a finding's own site
  4. a content hash of that specific source file (sha256 of its own bytes at scan time)
  5. the finding's own line/node identity (already present in each property's own existing
     output -- method_id / acquisition_call_id / lock_call_id / call_id -- never regressed here)
  6. a best-effort package-authored-vs-vendored flag, ONLY where cheaply determinable at scan
     time via a path heuristic -- NOT a substitute for #31's own later, authoritative
     classification, only a preservation of whatever signal would otherwise be lost

Does not itself decide whether a finding IS real, IS attributable, or IS reachable from JS --
those are #31 (provenance classification) and #32 (reachability) respectively, both explicitly
downstream of this module's own output.
"""
import base64
import hashlib
import os

VENDOR_PATH_MARKERS = ("vendor/", "vendor\\", "deps/", "deps\\", "third_party/", "third-party/",
                       "3rdparty/", "external/", "node_modules/")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dec(s):
    """Same base64-decode convention every scanner in this repo already uses for raw-fact
    text fields (methods.tsv's filename column is base64-encoded, per export_c_cpp_facts_v03.sc's
    own b64() wrapper)."""
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def classify_vendored_hint(relpath: str) -> str:
    """Best-effort, cheap, path-only heuristic -- explicitly NOT authoritative (task #31 owns
    the real classification). Never returns anything but PACKAGE_OWNED / VENDORED_HINT /
    UNKNOWN, so a caller can never mistake this for a confirmed provenance verdict."""
    if relpath is None:
        return "UNKNOWN"
    norm = relpath.replace("\\", "/").lower()
    for marker in VENDOR_PATH_MARKERS:
        if marker.replace("\\", "/").lower() in norm:
            return "VENDORED_HINT"
    return "PACKAGE_OWNED_HINT"


def build_source_manifest(pkg_dir: str, tarball_bytes: bytes, pkg_name: str, version: str) -> dict:
    """Walks the ALREADY-EXTRACTED package tree (pkg_dir) and returns a manifest with a
    source-tree hash (of the original tarball, not a re-derived tree walk -- the tarball is the
    single real artifact everything else was extracted from) plus a per-relative-path record of
    content hash and a best-effort vendored hint. Call this BEFORE header staging / c2cpg, and
    before anything under pkg_dir can be modified or deleted -- this is the one point in the
    pipeline where every real source byte is still present and unmodified.
    """
    source_tree_hash = sha256_hex(tarball_bytes)
    files = {}
    for root, _dirs, filenames in os.walk(pkg_dir):
        for fn in filenames:
            abspath = os.path.join(root, fn)
            relpath = os.path.relpath(abspath, pkg_dir)
            try:
                with open(abspath, "rb") as f:
                    content = f.read()
            except OSError:
                # unreadable (broken symlink, permission) -- record as such, never silently drop
                files[relpath] = {"content_hash": None, "provenance_hint": "UNREADABLE_AT_SCAN_TIME"}
                continue
            files[relpath] = {"content_hash": sha256_hex(content),
                               "provenance_hint": classify_vendored_hint(relpath)}
    return {
        "schema": "source-provenance-manifest/0.1",
        "package_name": pkg_name,
        "version": version,
        "source_tree_hash": source_tree_hash,
        "files": files,
    }


def load_method_file_map(cpp_raw_dir: str) -> dict:
    """Reads methods.tsv directly (id -> relative file path, base64-decoded) -- the SAME raw
    fact table export_c_cpp_facts_v03.sc already produces and run_pipeline_one.py already reads
    for every package, before deletion. Used to join R04/R05/LOCK_BALANCE/PROTECTED_FIELD
    findings (all keyed by method_id) and OOB_WRITE/READ/COMPARE candidates (keyed by the new
    additive function_id field, PROV-R01) back to a real source path -- WITHOUT modifying any of
    those scanners' own frozen verdict logic.
    """
    path = os.path.join(cpp_raw_dir, "methods.tsv")
    out = {}
    if not os.path.exists(path):
        return out
    for ln in open(path):
        if not ln.strip():
            continue
        parts = ln.rstrip("\n").split("\t")
        if len(parts) < 10:
            continue
        method_id = int(parts[0])
        file_field = dec(parts[4])
        out[method_id] = file_field
    return out


def _relpath_from_absolute_or_raw(raw_file_field: str, pkg_dir: str) -> str:
    """c2cpg's own methods.tsv filename field is usually already relative to the directory it
    was pointed at (pkg_dir), but defensively normalize an absolute path under pkg_dir to a
    relative one too, so manifest lookups (keyed by relpath) don't silently miss."""
    if not raw_file_field:
        return raw_file_field
    if os.path.isabs(raw_file_field) and raw_file_field.startswith(pkg_dir):
        return os.path.relpath(raw_file_field, pkg_dir)
    return raw_file_field.lstrip("./")


def enrich_finding(finding: dict, node_id, method_file_map: dict, manifest: dict, pkg_dir: str,
                    id_field_name: str) -> dict:
    """Attaches the six provenance fields to ONE finding/candidate dict, in place, and returns
    it. node_id is the method_id (R04/R05/LOCK_BALANCE/PROTECTED_FIELD) or function_id
    (OOB_WRITE/READ/COMPARE, via PROV-R01's additive field) to join through methods.tsv.
    id_field_name is recorded so a reader can see which of the finding's own existing fields
    was used as the join key (e.g. "method_id" or "function_id") -- never silently ambiguous.
    Fields 5 (line/node identity) are the finding's own PRE-EXISTING fields, untouched here.
    """
    finding["provenance"] = {
        "schema": "source-provenance-finding/0.1",
        "package_name": manifest.get("package_name"),
        "version": manifest.get("version"),
        "source_tree_hash": manifest.get("source_tree_hash"),
        "joined_via_field": id_field_name,
    }
    if node_id is None:
        finding["provenance"]["source_path"] = None
        finding["provenance"]["content_hash"] = None
        finding["provenance"]["provenance_hint"] = "UNRESOLVED_NODE_ID"
        return finding
    raw_file = method_file_map.get(node_id)
    if not raw_file:
        finding["provenance"]["source_path"] = None
        finding["provenance"]["content_hash"] = None
        finding["provenance"]["provenance_hint"] = "FILE_NOT_FOUND_IN_METHODS_TABLE"
        return finding
    relpath = _relpath_from_absolute_or_raw(raw_file, pkg_dir)
    finding["provenance"]["source_path"] = relpath
    entry = manifest.get("files", {}).get(relpath)
    if entry is None:
        # a real, disclosed mismatch: the raw-fact file path didn't match anything the manifest
        # walk found -- record it as such rather than silently guessing or dropping the finding.
        finding["provenance"]["content_hash"] = None
        finding["provenance"]["provenance_hint"] = "PATH_NOT_IN_MANIFEST"
        return finding
    finding["provenance"]["content_hash"] = entry["content_hash"]
    finding["provenance"]["provenance_hint"] = entry["provenance_hint"]
    return finding


def enrich_record(record: dict, cpp_raw_dir: str, manifest: dict, pkg_dir: str) -> dict:
    """Enriches every finding/candidate across all six properties' own output keys already
    present in `record` (whichever are present -- silently skips a key that isn't in this
    record, so this is safe to call regardless of which properties actually ran)."""
    method_file_map = load_method_file_map(cpp_raw_dir)

    for findings_key, id_field in (
        ("r04_findings", "method_id"),
        ("r05_findings", "method_id"),
        ("lock_balance_findings", "method_id"),
        ("protected_field_findings", "method_id"),
    ):
        for f in record.get(findings_key) or []:
            enrich_finding(f, f.get(id_field), method_file_map, manifest, pkg_dir, id_field)

    for candidates_key in ("oob_write_candidates", "oob_read_candidates", "oob_compare_candidates"):
        for c in record.get(candidates_key) or []:
            enrich_finding(c, c.get("function_id"), method_file_map, manifest, pkg_dir, "function_id")

    return record
