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
  2. TWO source-tree-level hashes, kept distinct per direct correction -- a single tarball hash
     was flagged as not being a real "source-tree hash": `tarball_sha256` (sha256 of the
     original, compressed tarball bytes -- a real, useful, but non-canonical artifact hash, since
     it is sensitive to gzip compression parameters, npm packaging metadata, and byte order, not
     just to the source content) and `source_tree_sha256` (a real, deterministic hash computed
     ONLY from each file's own normalized relative path and its own content hash, sorted by path
     -- reproducible regardless of tarball compression, extraction order, or filesystem walk
     order; two packages with byte-identical source content and layout, even if the tarball
     itself is re-gzipped differently, get the SAME source_tree_sha256, unlike tarball_sha256)
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

REPORTABILITY (direct correction, replacing an earlier, WRONG version of this section): a first
implementation set `finding["actionable"] = True` purely because provenance resolved -- a real
semantic defect, concretely confirmed on node-libcurl's own real finding (a site independently
confirmed elsewhere as a CONFIRMED FALSE POSITIVE) coming back marked actionable=True merely
because its source file was resolved. Provenance resolution is a NECESSARY condition for
reportability, never a SUFFICIENT one -- resolving a file tells you nothing about whether the
finding is a real candidate, whether its contract's premises are known to apply, or whether it
has already been adjudicated a false positive.

Five separate fields, never conflated:
  - `scanner_candidate` (bool): did the SCANNER's OWN verdict logic classify this as a real
    candidate, as opposed to an abstention/inapplicable/build-conflict/confirmed-safe record
    that happens to share the same output list? Determined per-property from each scanner's own
    real verdict vocabulary (see PROPERTY_CANDIDATE_RULES below) -- provenance.py does not
    invent this, it reads what the scanner itself already encoded.
  - `provenance.resolved` (bool): this module's own job, unchanged -- a real source_path +
    content_hash were both resolved.
  - `applicability_status` (str): whether this contract's real premises (e.g. exceptions-disabled
    build config for Resource Guard, JS-reachability for the others) are known to hold. NEVER set
    to "APPLICABLE" by this module -- it has no evidence to determine this; defaults to
    "NOT_YET_DETERMINED" unless the finding already carries a real value from elsewhere (a
    scanner's own applicability gate, or a later adjudication pass).
  - `adjudication_status` (str): whether this SPECIFIC finding has already been manually or
    automatically adjudicated. NEVER set to "CONFIRMED_FALSE_POSITIVE" by this module (it has no
    evidence to determine this either); defaults to "NOT_ADJUDICATED" unless already present.
  - `reportable` (bool): computed by the exact, one-way formula below -- ALL FOUR of the above
    must hold before a finding is ever reportable; failing any one is enough to make it False,
    and NOTHING in this module can force it True on its own:

      finding["reportable"] = (
          finding.get("scanner_candidate", False)
          and finding["provenance"]["resolved"]
          and finding.get("applicability_status") == "APPLICABLE"
          and finding.get("adjudication_status") != "CONFIRMED_FALSE_POSITIVE"
      )

  One-way rule: unresolved provenance -> reportable=False, always, unconditionally. Resolved
  provenance -> reportable is computed from the OTHER three fields, never automatically flipped
  true by resolution alone. A finding with reportable=False may still be RETAINED for diagnostic
  purposes (its own real classification/reason fields are never deleted) -- it must simply never
  be reported, published, or counted as a demonstrated vulnerability while `reportable` is False.
  `finding["actionable"]` from the prior, incorrect version of this module no longer exists --
  replaced entirely by `finding["reportable"]`.

  TERMINOLOGY BOUNDARY, stated explicitly so this is never misread downstream:
  `reportable=True` means "eligible to appear as a gated scanner candidate" -- it is the FLOOR a
  finding must clear before a human or a later pass may even consider it, not the CEILING of what
  it takes to call something a confirmed vulnerability. It certifies four narrow, mechanical
  facts (the scanner itself flagged a real candidate; its source is traceable; its contract's
  premises are known to hold; nothing has already adjudicated it a false positive) -- it does NOT
  certify exploitability, real-world impact, or that anyone has reviewed the specific site. An
  actual vulnerability claim still requires its own affirmative adjudication (e.g. a real
  `adjudication_status` value such as `CONFIRMED_TRUE_POSITIVE`, which this module does not
  define or assign -- that is entirely future, separate work, not implied by `reportable=True`
  alone). Do not report `reportable=True` findings as vulnerabilities; report them as gated
  candidates awaiting that separate adjudication step.
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


def compute_source_tree_sha256(files: dict) -> str:
    """A REAL, deterministic source-tree hash -- independent of tarball compression, extraction
    order, or filesystem walk order. Built from each file's own normalized relative path (forward
    slashes, so this is stable across OSes) and its own already-computed content hash, sorted by
    path, joined into one canonical blob, then hashed. Files this run could not read (see
    UNREADABLE_AT_SCAN_TIME below) contribute a fixed sentinel rather than being silently
    skipped, so a tree missing a readable file hashes differently from one that has it.
    """
    lines = []
    for relpath in sorted(files.keys()):
        norm = relpath.replace("\\", "/")
        content_hash = files[relpath].get("content_hash") or "UNREADABLE"
        lines.append(f"{norm}\t{content_hash}")
    blob = "\n".join(lines).encode("utf-8")
    return sha256_hex(blob)


def build_source_manifest(pkg_dir: str, tarball_bytes: bytes, pkg_name: str, version: str) -> dict:
    """Walks the ALREADY-EXTRACTED package tree (pkg_dir) and returns a manifest with TWO
    source-tree-level hashes (tarball_sha256 -- the original compressed tarball's own bytes, a
    real but non-canonical artifact hash; source_tree_sha256 -- a real, deterministic hash of
    normalized relative paths + content hashes only, reproducible independent of tarball
    compression/extraction/walk order) plus a per-relative-path record of content hash and a
    best-effort vendored hint. Call this BEFORE header staging / c2cpg, and before anything
    under pkg_dir can be modified or deleted -- this is the one point in the pipeline where
    every real source byte is still present and unmodified.
    """
    tarball_sha256 = sha256_hex(tarball_bytes)
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
        "schema": "source-provenance-manifest/0.2",
        "package_name": pkg_name,
        "version": version,
        "tarball_sha256": tarball_sha256,
        "source_tree_sha256": compute_source_tree_sha256(files),
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


def _unresolved(finding: dict, reason: str) -> dict:
    """Marks a finding's provenance as unresolved, FAIL-CLOSED: source_path/content_hash stay
    None, provenance_hint names the real reason, provenance["resolved"] is explicitly False.
    Does NOT set finding["reportable"] -- that is computed once, uniformly, by
    finalize_reportability(), which honors the one-way rule (unresolved -> reportable=False)
    regardless of this function's own caller."""
    finding["provenance"]["source_path"] = None
    finding["provenance"]["content_hash"] = None
    finding["provenance"]["provenance_hint"] = reason
    finding["provenance"]["resolved"] = False
    return finding


def enrich_finding(finding: dict, node_id, method_file_map: dict, manifest: dict, pkg_dir: str,
                    id_field_name: str) -> dict:
    """Attaches ONLY the provenance fields (package identity, both tree hashes, source_path,
    content_hash, provenance_hint, resolved) to ONE finding/candidate dict, in place, and
    returns it. Does NOT set scanner_candidate/applicability_status/adjudication_status/
    reportable -- call finalize_reportability() separately (enrich_record does this
    automatically) so provenance resolution and reportability stay two clearly separate steps,
    never conflated.

    node_id is the method_id (R04/R05/LOCK_BALANCE/PROTECTED_FIELD) or function_id
    (OOB_WRITE/READ/COMPARE, via PROV-R01's additive field) to join through methods.tsv.
    id_field_name is recorded so a reader can see which of the finding's own existing fields
    was used as the join key -- never silently ambiguous. Fields 5 (line/node identity) are the
    finding's own PRE-EXISTING fields, untouched here.
    """
    finding["provenance"] = {
        "schema": "source-provenance-finding/0.3",
        "package_name": manifest.get("package_name"),
        "version": manifest.get("version"),
        "tarball_sha256": manifest.get("tarball_sha256"),
        "source_tree_sha256": manifest.get("source_tree_sha256"),
        "joined_via_field": id_field_name,
    }
    if node_id is None:
        return _unresolved(finding, "UNRESOLVED_NODE_ID")
    raw_file = method_file_map.get(node_id)
    if not raw_file:
        return _unresolved(finding, "FILE_NOT_FOUND_IN_METHODS_TABLE")
    relpath = _relpath_from_absolute_or_raw(raw_file, pkg_dir)
    finding["provenance"]["source_path"] = relpath
    entry = manifest.get("files", {}).get(relpath)
    if entry is None:
        # a real, disclosed mismatch: the raw-fact file path didn't match anything the manifest
        # walk found -- record it as such rather than silently guessing or dropping the finding.
        return _unresolved(finding, "PATH_NOT_IN_MANIFEST")
    if entry.get("content_hash") is None:
        # the manifest walk found this path but could not read it (UNREADABLE_AT_SCAN_TIME) --
        # a real path match with no real content hash is still not a resolved finding.
        finding["provenance"]["provenance_hint"] = entry["provenance_hint"]
        return _unresolved(finding, "SOURCE_FILE_UNREADABLE_AT_SCAN_TIME")
    finding["provenance"]["content_hash"] = entry["content_hash"]
    finding["provenance"]["provenance_hint"] = entry["provenance_hint"]
    finding["provenance"]["resolved"] = True
    return finding


# PROPERTY_CANDIDATE_RULES: which of a scanner's OWN real verdict values represent a genuine
# candidate, as opposed to an abstention/inapplicable/build-conflict/confirmed-safe record that
# happens to share the same output list. Read directly from each scanner's own source, not
# guessed:
#   - R04/R05's own "findings" list mixes VALUE_ACQUISITION_SEMANTICS_UNRESOLVED (abstention),
#     CONTRACT_NOT_APPLICABLE, BUILD_CONFIGURATION_CONFLICT/UNRESOLVED (all abstentions), and
#     the real classification pair VALUE_ACQUISITION_GUARD_ESTABLISHED (real negative -- a
#     confirmed-safe guard, not a candidate) / VALUE_ACQUISITION_GUARD_MISSING (the one real
#     positive candidate verdict). Only the latter is scanner_candidate=True.
#   - LOCK_BALANCE/PROTECTED_FIELD/OOB_WRITE/OOB_READ/OOB_COMPARE were checked directly: every
#     item their own findings/candidates lists ever contain IS already a real candidate (no
#     abstention-shaped entries are ever appended to those specific lists -- abstentions there
#     only ever increment a separate classification COUNTER, never enter the list itself) -- so
#     scanner_candidate=True unconditionally is correct for those five.
_R04_R05_CANDIDATE_VERDICTS = {"VALUE_ACQUISITION_GUARD_MISSING"}

PROPERTY_CANDIDATE_RULES = {
    "r04_findings": lambda f: f.get("verdict") in _R04_R05_CANDIDATE_VERDICTS,
    "r05_findings": lambda f: f.get("verdict") in _R04_R05_CANDIDATE_VERDICTS,
    "lock_balance_findings": lambda f: True,
    "protected_field_findings": lambda f: True,
    "oob_write_candidates": lambda f: True,
    "oob_index_write_candidates": lambda f: True,  # overnight-diagnostic-100: task #44's own
    # emit_candidates() was checked directly (same discipline as the other four OOB keys) --
    # it only ever appends a real CANDIDATE, both for its pre-existing fixed-array path and the
    # new PARAM-CAP-R01 path; abstentions never enter this list.
    "oob_read_candidates": lambda f: True,
    "oob_compare_candidates": lambda f: True,
}


def finalize_reportability(finding: dict, is_scanner_candidate: bool) -> dict:
    """Sets scanner_candidate (from the caller's own per-property rule, never invented here),
    defaults applicability_status/adjudication_status to non-affirmative sentinels UNLESS the
    finding already carries a real value from elsewhere (never overwrites an existing value),
    then computes reportable via the exact, one-way formula. Must be called AFTER
    enrich_finding() has set finding["provenance"]["resolved"].

    reportable=True means "eligible to appear as a gated scanner candidate," never "confirmed
    vulnerability" -- see this module's own top-level docstring, TERMINOLOGY BOUNDARY. A real
    vulnerability claim needs its own separate, affirmative adjudication step this function does
    not perform.
    """
    finding.setdefault("scanner_candidate", is_scanner_candidate)
    finding.setdefault("applicability_status", "NOT_YET_DETERMINED")
    finding.setdefault("adjudication_status", "NOT_ADJUDICATED")
    finding["reportable"] = (
        bool(finding.get("scanner_candidate", False))
        and bool(finding.get("provenance", {}).get("resolved", False))
        and finding.get("applicability_status") == "APPLICABLE"
        and finding.get("adjudication_status") != "CONFIRMED_FALSE_POSITIVE"
    )
    return finding


def enrich_record(record: dict, cpp_raw_dir: str, manifest: dict, pkg_dir: str) -> dict:
    """Enriches every finding/candidate across all six properties' own output keys already
    present in `record` (whichever are present -- silently skips a key that isn't in this
    record, so this is safe to call regardless of which properties actually ran). Attaches
    provenance, then computes reportability per PROPERTY_CANDIDATE_RULES -- never the reverse
    order, and never lets provenance resolution alone imply reportable."""
    method_file_map = load_method_file_map(cpp_raw_dir)

    for findings_key, id_field in (
        ("r04_findings", "method_id"),
        ("r05_findings", "method_id"),
        ("lock_balance_findings", "method_id"),
        ("protected_field_findings", "method_id"),
    ):
        candidate_rule = PROPERTY_CANDIDATE_RULES[findings_key]
        for f in record.get(findings_key) or []:
            enrich_finding(f, f.get(id_field), method_file_map, manifest, pkg_dir, id_field)
            finalize_reportability(f, candidate_rule(f))

    for candidates_key in ("oob_write_candidates", "oob_index_write_candidates",
                           "oob_read_candidates", "oob_compare_candidates"):
        candidate_rule = PROPERTY_CANDIDATE_RULES[candidates_key]
        for c in record.get(candidates_key) or []:
            enrich_finding(c, c.get("function_id"), method_file_map, manifest, pkg_dir, "function_id")
            finalize_reportability(c, candidate_rule(c))

    return record
