#!/usr/bin/env python3
"""DIAGNOSTIC re-scan of the held-out failure funnel (ANALYSIS ONLY; changes no scanner code).
For each built body (175 vulnerable + 101 non-vulnerable SecVulEval function packets) it re-runs
the frozen CPG build (main scan only) and records, per LABELED write site:
  * total_cpp_nodes (0/near-0 => whole-packet parse failure);
  * labeled_line_present + nearest_node_distance (partial-region parse drop);
  * write_shape at the labeled line (deref / member / index / scalar / copy_call / decl / none);
  * for recognized sites, an evidence trace (dest decl kind -> extent/capacity lookup).
Deterministic re-scan of the same frozen pipeline; no producer/capability/normalizer changes.

Usage: JOERN=... REPO=... python3 heldout_diagnose.py <outfile.jsonl>
"""
import gzip, hashlib, json, os, re, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_write_site_dedup as WSD
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
GZ = ("/tmp/claude-0/-home-user-bug-tracker/0fd64c6d-7e3d-554b-9af8-02d9e6597995/"
      "scratchpad/secvuleval_full.jsonl.gz")
STUDY = os.path.join(HERE, "study")
MEMB = re.compile(r"^[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*$")
IDX = re.compile(r"^[A-Za-z_]\w*\s*\[")
COPY = {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "snprintf", "sprintf",
        "memset", "bcopy", "wmemcpy", "copy_from_user", "copy_to_user"}


def _norm(s): return re.sub(r"\s+", " ", (s or "").strip())


def write_shape(cj, L, dest):
    """Classify the write form at labeled line L from the built CPG."""
    calls = [c for c in cj.get("calls", []) if c.get("line") == L]
    # a library copy/format sink on the line
    for c in calls:
        if c.get("name") in COPY:
            return "copy_call:" + c["name"]
    # an assignment on the line -> classify its target
    for c in calls:
        if c.get("name") == "<operator>.assignment" and c.get("arguments"):
            tgt = _norm(sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "")
            if tgt.startswith("*"):
                return "deref_write"
            if MEMB.match(tgt):
                return "member_write"
            if IDX.match(tgt):
                return "index_write"
            return "scalar_or_pointer_assign"
    # a local declaration at L
    if any(l.get("line") == L for l in cj.get("locals", [])):
        return "declaration"
    if calls:
        return "other_call_only"
    return "no_write_node"


def evidence_trace(cj, L, dest):
    """For a recognized site: resolve the dest declaration and look up its extent/capacity."""
    index = WSD.build_index(cj)
    stack = v2.compute_stack_fixed_array_extents(cj)
    heap = AE.compute_allocation_extents(cj)
    base = WSD._root_ident(dest or "")
    # find an assignment/copy call at L touching the dest base
    node = None
    for c in cj.get("calls", []):
        if c.get("line") == L and base and base in (c.get("code") or ""):
            node = c; break
    decl_kind = "unresolved"
    fid = node.get("enclosing_function_id") if node else None
    if node and node.get("arguments"):
        a0 = sorted(node["arguments"], key=lambda a: a.get("index", 0))[0]
        idid = WSD._descend_to_identifier(a0, index["call_by_id"])
        ident = index["ident_by_id"].get(idid) if idid else None
        refs = (ident.get("ref_target_ids") if ident else None) or []
        decl = refs[0] if len(refs) == 1 else None
        if decl in index["params_by_id"]:
            decl_kind = "parameter"
        elif decl in index["locals_by_id"]:
            decl_kind = "local"
        elif MEMB.match(_norm(dest or "")):
            decl_kind = "struct_field"
    stack_hit = any(k[0] == fid for k in stack) if fid else False
    heap_hit = any(k[0] == fid for k in heap) if fid else False
    return {"dest_base": base, "decl_kind": decl_kind,
            "stack_extent_in_fn": stack_hit, "heap_extent_in_fn": heap_hit,
            "reason_evidence_absent": (
                "dest is a %s -> no independently-established byte extent" % decl_kind
                if decl_kind in ("parameter", "struct_field", "unresolved") else
                "dest is a local but no fixed-array/alloc extent bound")}


def load_built():
    rows = []
    for l in open(os.path.join(STUDY, "heldout_run", "raw_sites.jsonl")):
        r = json.loads(l)
        if r.get("pool_source") == "secvuleval_full" and r.get("stage2_build_parse_ok"):
            r["is_vulnerable"] = True; rows.append(r)
    for l in open(os.path.join(STUDY, "heldout_negatives", "raw_negatives.jsonl")):
        r = json.loads(l)
        if r.get("stage2_build_parse_ok"):
            r["is_vulnerable"] = False; rows.append(r)
    return rows


def main():
    outp = sys.argv[1] if len(sys.argv) > 1 else "/tmp/diag.jsonl"
    man = json.load(open(os.path.join(STUDY, "secvuleval_full", "FROZEN_heldout.json")))
    sid2sha = {s["site_id"]: s["func_body_sha256"] for s in man["sites"]}
    bodies = {}
    for ln in gzip.open(GZ, "rt"):
        o = json.loads(ln)
        h = hashlib.sha256(o["func_body"].encode()).hexdigest()
        bodies.setdefault(h, o["func_body"])
    out = open(outp, "w")
    for r in load_built():
        sha = sid2sha.get(r["site_id"])
        body = bodies.get(sha)
        row = {"site_id": r["site_id"], "func_name": r.get("func_name"),
               "is_vulnerable": r["is_vulnerable"], "write_kind": r.get("write_kind"),
               "family_id": r.get("family_id"), "write_dest": r.get("write_dest"),
               "mapped": bool(r.get("stage3_labeled_write_mapped")),
               "recognized": bool(r.get("stage4_recognized"))}
        if body is None:
            row["error"] = "body_missing"; out.write(json.dumps(row) + "\n"); continue
        work = tempfile.mkdtemp(); open(os.path.join(work, "body.c"), "w").write(body)
        o = os.path.join(work, "out")
        subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), work, o],
                       capture_output=True, text=True)
        cpp = os.path.join(o, "cpp.json")
        if not os.path.exists(cpp):
            row["error"] = "rescan_no_cpp"; out.write(json.dumps(row) + "\n"); continue
        cj = json.load(open(cpp))
        total = len(cj.get("calls", [])) + len(cj.get("identifiers", [])) + len(cj.get("locals", []))
        row["total_cpp_nodes"] = total
        bl = body.splitlines(); nl = _norm(r.get("write_line"))
        cand = [i + 1 for i, x in enumerate(bl) if nl and _norm(x) == nl] or \
               [i + 1 for i, x in enumerate(bl) if nl and nl in _norm(x)]
        node_lines = {c.get("line") for c in cj.get("calls", [])} | \
                     {n.get("line") for n in cj.get("identifiers", [])} | \
                     {n.get("line") for n in cj.get("locals", [])}
        node_lines.discard(None)
        L = cand[0] if cand else None
        row["labeled_line"] = L
        row["labeled_line_present"] = bool(L in node_lines) if L else False
        row["nearest_node_distance"] = (min((abs(x - L) for x in node_lines), default=None)
                                        if L and node_lines else None)
        row["parse_class"] = ("empty_or_degenerate_cpg" if total < 10 else
                              ("labeled_region_dropped" if (L and not row["labeled_line_present"])
                               else "labeled_line_parsed"))
        if L:
            row["write_shape"] = write_shape(cj, L, r.get("write_dest"))
        if r.get("stage4_recognized") and L:
            row["evidence_trace"] = evidence_trace(cj, L, r.get("write_dest"))
        out.write(json.dumps(row) + "\n"); out.flush()
    out.close()
    print("DIAG_WRITTEN", outp)


if __name__ == "__main__":
    main()
