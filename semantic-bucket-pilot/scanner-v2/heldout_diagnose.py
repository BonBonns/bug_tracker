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
import heldout_run as HR   # reuse PROD (3 frozen producers)
import cap_addr_indexed as C1
import cap_wrapper_summary as C2W
import cap_counted_loop_writer as C2L
import cap_decoder_contract as C4


def _recognized_no_cap3(cpp_path):
    """Run every producer/capability EXCEPT cap3 (whose for-structure needs a joern scan; it
    recognized nothing in the actual run). Pure-Python; no joern. Returns (producer,function,
    line,dest) tuples."""
    out = []
    for pname, m in HR.PROD.items():
        for r in m.analyze_operations(cpp_path):
            out.append({"producer": pname, "function": r.get("function"),
                        "line": r.get("line"), "dest": r.get("dest")})
    for r in C1.analyze_addr_indexed(cpp_path):
        out.append({"producer": "cap1_addr_indexed", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest")})
    ops, _ = C2W.analyze_wrapper_calls(cpp_path)
    for r in ops:
        out.append({"producer": "cap2_wrapper", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest")})
    for r in C2L.analyze_counted_writers(cpp_path):
        out.append({"producer": "cap2_counted_loop", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest")})
    for r in C4.analyze_decoder_calls(cpp_path):
        out.append({"producer": "cap4_decoder", "function": r.get("function"),
                    "line": r.get("line"), "dest": r.get("dest")})
    return out
GZ = ("/tmp/claude-0/-home-user-bug-tracker/0fd64c6d-7e3d-554b-9af8-02d9e6597995/"
      "scratchpad/secvuleval_full.jsonl.gz")
STUDY = os.path.join(HERE, "study")
CACHE = os.path.join(STUDY, "heldout_diagnosis", "cache")   # persisted cpp.json (gitignored)
MEMB = re.compile(r"^[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*$")
IDX = re.compile(r"^[A-Za-z_]\w*\s*\[")
COPY = {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "snprintf", "sprintf",
        "memset", "bcopy", "wmemcpy", "copy_from_user", "copy_to_user"}


def _norm(s): return re.sub(r"\s+", " ", (s or "").strip())


# ---- STEP 0: label-validity classifier (text-based; no CPG needed) -----------------------
_TYPEKW = (r'(?:const|volatile|static|inline|register|unsigned|signed|struct|enum|union|char|'
           r'int|short|long|void|bool|float|double|size_t|ssize_t|ptrdiff_t|u8|u16|u32|u64|'
           r's8|s16|s32|s64|__u8|__u16|__u32|__u64|__le16|__le32|__le64|__be16|__be32|__be64|'
           r'uint\w*|int\w*|\w+_t)')
_GUARD = re.compile(r'^\s*(if|while|for|switch|return|break|continue|goto|BUG_ON|WARN\w*|'
                    r'assert|else|EXPORT_)')
_MEMFN = (r'(?:memcpy|memmove|memset|strcpy|strncpy|strlcpy|strcat|strncat|snprintf|sprintf|'
          r'vsnprintf|scnprintf|bcopy|copy_from_user|copy_to_user|put_unaligned\w*)')


def label_class(wl, dest):
    """Classify a labeled SecVulEval site by what its target actually is, so declarations /
    guards / reads are not counted as scanner recognition failures."""
    wl = (wl or "").strip(); dest = (dest or "").strip()
    if wl.startswith("/*") or wl.startswith("//"):
        return "comment_or_nonstatement"
    base = re.split(r'->|\.|\[', dest)[0].lstrip("*& ").strip()
    if not base:
        return "ambiguous"
    b = re.escape(base)
    if re.search(r'(?:^|[;{(,])\s*(?:' + _TYPEKW + r'\b[\w\s]*?)(?:\*\s*)*' + b + r'\b\s*(?:=|;|,|\[)', wl):
        if re.search(r'\b' + b + r'\b', wl.split("=")[0]):
            return "pointer_or_var_declaration"
    if _GUARD.match(wl) and not re.search(r'\b' + b + r'\s*(?:\[[^\]]*\])?\s*=(?!=)', wl):
        return "guard_or_control"
    if re.match(r'\s*(?:[\w.\->]+\s*=\s*)?' + _MEMFN + r'\s*\(\s*&?\s*' + b + r'\b', wl):
        return "destination_write"
    if re.search(r'(?:^|[^=!<>])\*\s*' + b + r'\s*(?:\+\+|--)?\s*=(?!=)', wl):
        return "destination_write"
    if re.search(r'(?:^|[^\w>])' + b + r'\s*\[[^\]]*\]\s*=(?!=)', wl):
        return "destination_write"
    if re.search(r'(?:^|[^\w>])' + b + r'\s*(?:->|\.)\s*\w+(?:\s*\[[^\]]*\])?\s*=(?!=)', wl):
        return "destination_write"
    if re.search(r'(?:^|[^=!<>*\w.>])' + b + r'\s*=(?!=)', wl):
        return "scalar_pointer_assignment"
    if re.search(r'\b' + b + r'\b', wl):
        return "read_or_deref_only"
    return "ambiguous"


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


def _dest_extent(cj, fid, base, index):
    """Does the dest base resolve to an INDEPENDENTLY-ESTABLISHED extent (the exact gate the
    capacity producers require)? Uses the producers' own extent functions."""
    stack = v2.compute_stack_fixed_array_extents(cj)
    heap = AE.compute_allocation_extents(cj)
    # local fixed array named base?
    for l in cj.get("locals", []):
        if l.get("method_id") == fid and l.get("name") == base and (fid, l.get("id")) in stack:
            return "stack_fixed_array"
    if (fid, base) in heap and heap[(fid, base)].get("establishment_status") == "ESTABLISHED":
        return "heap_literal_allocation"
    return None


def producer_facts(cj, L, dest, cpp_path):
    """The ACTUAL producer gate for a mapped write: which producers even recognize it, and the
    concrete precondition that decides them (computed with the producers' own functions), NOT
    inferred from source shape. cap3 (needs a joern for-structure scan) is excluded here."""
    index = WSD.build_index(cj)
    base = WSD._root_ident(dest or "")
    calls_at_L = [c for c in cj.get("calls", []) if c.get("line") == L]
    sink = sorted({c["name"] for c in calls_at_L if c.get("name") in COPY})
    # write node + enclosing fn + dest declaration kind
    node = next((c for c in calls_at_L if base and base in (c.get("code") or "")), None)
    fid = node.get("enclosing_function_id") if node else None
    decl_kind = "unresolved"
    if node and node.get("arguments"):
        a0 = sorted(node["arguments"], key=lambda a: a.get("index", 0))[0]
        idid = WSD._descend_to_identifier(a0, index["call_by_id"])
        ident = index["ident_by_id"].get(idid) if idid else None
        refs = (ident.get("ref_target_ids") if ident else None) or []
        d = refs[0] if len(refs) == 1 else None
        if d in index["params_by_id"]:
            decl_kind = "parameter"
        elif d in index["locals_by_id"]:
            decl_kind = "local"
    if MEMB.match(_norm(dest or "")):
        decl_kind = "struct_field"
    extent = _dest_extent(cj, fid, base, index) if fid else None
    # ACTUAL recognition per pure-Python producer (run them; see who fires at func L)
    fn = index["funcs"].get(fid, {}).get("name") if fid else None
    fired = []
    for r in _recognized_no_cap3(cpp_path):
        if r.get("line") == L and (fn is None or r.get("function") == fn):
            fired.append(r["producer"])
    # earliest failing gate (faithful: modeled-form gate, then established-capacity gate)
    if not fired:
        modeled = bool(sink) or _norm(dest or "").startswith("*") or MEMB.match(_norm(dest or ""))
        if not modeled:
            gate = "write_form_not_in_any_producer_domain"
        elif extent is None:
            gate = "destination_capacity_not_established (decl=%s)" % decl_kind
        else:
            gate = "capacity_established_but_relation_not_promoted"
    else:
        gate = "recognized_by:" + ",".join(sorted(set(fired)))
    return {"sink_call_at_line": sink, "dest_decl_kind": decl_kind,
            "dest_extent_established": extent, "producers_fired": sorted(set(fired)),
            "failing_gate": gate}


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
    os.makedirs(CACHE, exist_ok=True)
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
        row["label_class"] = label_class(r.get("write_line"), r.get("write_dest"))
        if body is None:
            row["error"] = "body_missing"; out.write(json.dumps(row) + "\n"); continue
        # PERSIST cpp.json to the cache so no later analysis ever re-scans.
        cpp = os.path.join(CACHE, r["site_id"] + ".cpp.json")
        if not os.path.exists(cpp):
            work = tempfile.mkdtemp(); open(os.path.join(work, "body.c"), "w").write(body)
            o = os.path.join(work, "out")
            subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), work, o],
                           capture_output=True, text=True)
            src = os.path.join(o, "cpp.json")
            if os.path.exists(src):
                import shutil; shutil.copyfile(src, cpp)
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
        if row["mapped"] and L:
            row["producer_facts"] = producer_facts(cj, L, r.get("write_dest"), cpp)
        if r.get("stage4_recognized") and L:
            row["evidence_trace"] = evidence_trace(cj, L, r.get("write_dest"))
        out.write(json.dumps(row) + "\n"); out.flush()
    out.close()
    print("DIAG_WRITTEN", outp)


if __name__ == "__main__":
    main()
