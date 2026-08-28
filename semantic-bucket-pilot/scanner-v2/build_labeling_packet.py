#!/usr/bin/env python3
"""Stage 1 — build the BLINDED labeling packet (mechanical; no model judgment).

For each of the 438 case instances, extract from SOURCE ONLY the material a security
reviewer needs to assign VULNERABLE / SAFE / UNRESOLVED with an evidence basis:
  * neutral instance + family ids (opaque hashes; no revision-side encoding);
  * the operation (write statement + location);
  * the enclosing function source (surrounding context, arithmetic, guards);
  * the destination declaration + capacity (from source);
  * the write-length expression (+ in-function definition of its variable if present);
  * the enclosing control-flow guards (if/for/while/switch headers that brace-enclose
    the write), extracted mechanically;
  * reachability evidence: storage class (static?) and the list of call sites;
  * sibling instance ids so paired revisions can be compared — labeled neutrally.

EXCLUDED (asserted absent): V1/V2 routes, bucket names, scanner conclusions
(uncertainty_bucket / unresolved_property / established_property), A/B/C outputs,
"pre_patch"/"post_patch"/"vuln"/"vulnerable revision" labels, and any generated
prose summary. Nothing here is an interpretation; every field is copied source text
or a mechanical fact. The model does NOT assign labels.

Output: study/stage1_labeling_packet.jsonl (one row per instance).
The empty label sidecar schema is documented in STAGE1_LABELING.md; labels are
written to study/stage1_labels.jsonl during review and frozen separately.
"""
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study")
EXP = "/tmp/expansion"

FORBIDDEN = [  # scanner/route tokens that must never reach the reviewer
    "recommended_route", "v1_route", "v2_route", "additional_evidence_required",
    "semantic_relationship_review", "range_arithmetic_review", "deterministic_complete",
    "uncertainty_bucket", "unresolved_property", "established_property", "llm_eligible",
    "_v2_", "pre_patch", "post_patch", "revision_side", "stack_fixed_array",
]

_FILE = {}


def flines(scan_side, rel):
    k = (scan_side, rel)
    if k not in _FILE:
        p = os.path.join(EXP, scan_side, "csrc", rel)
        try:
            _FILE[k] = open(p, errors="replace").read().splitlines()
        except OSError:
            _FILE[k] = None
    return _FILE[k]


def norm_fn(fn):
    return re.sub(r"<[^>]*>\d*", "", fn or "")


def func_span(scan_side, rel, fn, op_line):
    """Return (start_line, end_line, body_lines) of the function definition whose
    body contains op_line. 1-indexed inclusive. Distinguishes a definition from a
    prototype by matching the parameter parens, then requiring '{' (not ';')."""
    lines = flines(scan_side, rel)
    if not lines:
        return None
    txt = "\n".join(lines)
    n = len(txt)
    for m in re.finditer(r"\b" + re.escape(fn) + r"\s*\(", txt):
        # match the parameter-list parens starting at the '(' just before m.end()
        p = txt.rfind("(", m.start(), m.end())
        depth, i = 0, p
        while i < n:
            if txt[i] == "(":
                depth += 1
            elif txt[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        j = i + 1
        while j < n and txt[j] in " \t\r\n":
            j += 1
        if j >= n or txt[j] != "{":
            continue                      # prototype / call site, not a definition
        b = j
        depth, k = 0, b
        while k < n:
            if txt[k] == "{":
                depth += 1
            elif txt[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        s_ln = txt.count("\n", 0, b) + 1
        e_ln = txt.count("\n", 0, k) + 1
        sig_ln = txt.count("\n", 0, m.start()) + 1
        if s_ln <= op_line <= e_ln:
            return sig_ln, e_ln, lines[sig_ln - 1:e_ln]
    return None


def window_fallback(scan_side, rel, op_line, radius=25):
    lines = flines(scan_side, rel)
    if not lines:
        return None
    lo = max(1, op_line - radius)
    hi = min(len(lines), op_line + radius)
    return lo, hi, lines[lo - 1:hi]


def declaration_line(body_lines, dest):
    dre = re.compile(r"\b([A-Za-z_][\w ]*?)\s+" + re.escape(dest) + r"\s*\[")
    dre2 = re.compile(r"\b" + re.escape(dest) + r"\s*\[")
    for ln in body_lines:
        if dre.search(ln) or (dre2.search(ln) and ("[" in ln)):
            if "=" not in ln.split(dest)[0] and ("," in ln or re.search(r"\]\s*;", ln) or "]" in ln):
                return ln.strip()
    return None


def enclosing_guards(scan_side, rel, sig_ln, op_line):
    """Mechanical: control-flow header lines (if/for/while/switch) whose block
    brace-encloses op_line, from function start down to the write."""
    lines = flines(scan_side, rel)
    guards = []
    stack = []
    depth = 0
    header_re = re.compile(r"\b(if|for|while|switch|else\s+if)\b")
    for ln_no in range(sig_ln, op_line + 1):
        ln = lines[ln_no - 1]
        # record a header seen just before an opening brace / block
        if header_re.search(ln) and ln_no < op_line:
            pending = ln.strip()
        else:
            pending = None
        opens = ln.count("{")
        closes = ln.count("}")
        if pending and opens:
            stack.append((depth, pending))
        depth += opens - closes
        while stack and depth <= stack[-1][0]:
            stack.pop()
    return [g for _, g in stack]


_CALLERS = {}


def callers(scan_side, fn, limit=15):
    key = (scan_side, fn)
    if key in _CALLERS:
        return _CALLERS[key]
    root = os.path.join(EXP, scan_side, "csrc")
    cre = re.compile(r"(^|[^\w])" + re.escape(fn) + r"\s*\(")
    defre = re.compile(r"\b" + re.escape(fn) + r"\s*\([^;]*\)\s*\{?\s*$")
    hits = []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith((".c",)):
                continue
            p = os.path.join(dp, f)
            try:
                for i, ln in enumerate(open(p, errors="replace"), 1):
                    if cre.search(ln) and "(" in ln and not defre.search(ln.strip()):
                        # exclude the definition/prototype lines heuristically
                        if re.search(r"\b" + re.escape(fn) + r"\s*\(", ln) and (";" in ln or "," in ln or ")" in ln) and "{" not in ln:
                            rel = os.path.relpath(p, root)
                            hits.append({"file": rel, "line": i, "call_text": ln.strip()})
                            if len(hits) >= limit:
                                raise StopIteration
            except StopIteration:
                break
        if len(hits) >= limit:
            break
    _CALLERS[key] = hits
    return hits


def storage_is_static(body_lines):
    sig = body_lines[0] if body_lines else ""
    return "static" in sig.split("(")[0]


def main():
    insts = [json.loads(l) for l in open(os.path.join(OUT, "instances.jsonl"))]
    fam_siblings = defaultdict(list)
    for it in insts:
        fam_siblings[it["family_id"]].append(it["instance_id"])

    rows = []
    missing_ctx = 0
    for it in insts:
        iid = it["instance_id"]
        # a concrete observed (scan,side) for this instance's source view
        scan_side = sorted(it["line_by_scan"])[0]
        op_line = it["line_by_scan"][scan_side]
        rel = it["file"]
        fn = norm_fn(it["function"])
        span = func_span(scan_side, rel, fn, op_line)
        context_kind = "full_function"
        if span:
            sig_ln, e_ln, body = span
            decl = declaration_line(body, it["dest"])
            guards = enclosing_guards(scan_side, rel, sig_ln, op_line)
            static = storage_is_static(body)
            body_text = "\n".join(body)
        else:
            missing_ctx += 1
            context_kind = "window_fallback"
            wf = window_fallback(scan_side, rel, op_line)
            if wf:
                sig_ln, e_ln, body = wf
                decl = declaration_line(body, it["dest"])
                guards = []                      # not reliable without the full body
                static = None
                body_text = "\n".join(body)
            else:
                context_kind = "unavailable"
                sig_ln = e_ln = decl = static = body_text = None
                guards = []
        row = {
            "packet_instance_id": iid,                 # opaque; no revision encoding
            "packet_family_id": it["family_id"],       # opaque grouping only
            "sibling_instance_ids": sorted(x for x in fam_siblings[it["family_id"]] if x != iid),
            "operation": {
                "file": rel, "function": fn, "destination": it["dest"],
                "write_statement": it["write_stmt"], "write_line": op_line,
            },
            "destination_capacity_evidence": {
                "declared_element_type": it["element_type"],
                "declared_element_count": it["element_count"],
                "capacity_expression": it["capacity_expr"],
                "declaration_source_line": decl,
            },
            "write_length": {
                "write_length_expression": it["width_expr"],
            },
            "enclosing_guards": guards,
            "reachability_evidence": {
                "function_storage_static": static,
                "call_sites": callers(scan_side, fn),
            },
            "function_source": body_text,
            "context_kind": context_kind,
            "source_view": {"scan_dir": scan_side.split("/")[0], "line": op_line},
        }
        rows.append(row)

    # ---- neutrality validation (no forbidden token anywhere in the packet) ----
    blob = json.dumps(rows)
    leaked = sorted({t for t in FORBIDDEN if t in blob})
    assert not leaked, f"packet leaks forbidden scanner/routing tokens: {leaked}"
    # completeness: how many rows have full function context
    have_ctx = sum(1 for r in rows if r["function_source"])

    pkt_path = os.path.join(OUT, "stage1_labeling_packet.jsonl")
    with open(pkt_path, "w") as fh:
        for r in sorted(rows, key=lambda x: x["packet_instance_id"]):
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    # split-aware stats (from the manifest; not shown to reviewers)
    split_of = {it["instance_id"]: it["split"] for it in insts}
    from collections import Counter
    by_split = Counter(split_of[r["packet_instance_id"]] for r in rows)
    dev_ctx = sum(1 for r in rows
                  if split_of[r["packet_instance_id"]] == "dev" and r["function_source"])
    dev_n = by_split["dev"]

    from collections import Counter as _C
    ck = _C(r["context_kind"] for r in rows)
    print(f"instances in packet          : {len(rows)}")
    print(f"neutrality check             : PASS (no forbidden tokens)")
    print(f"context kind                 : {dict(ck)}  (window_fallback flagged for reviewers)")
    print(f"by split                     : {dict(by_split)}")
    print(f"DEV validation subset        : {dev_n} instances, {dev_ctx} with full context")
    # eyeball two dev rows
    shown = 0
    for r in rows:
        if split_of[r["packet_instance_id"]] == "dev" and r["function_source"] and shown < 2:
            print(f"\n--- DEV sample {shown+1}: {r['packet_instance_id']} "
                  f"({r['operation']['function']}:{r['operation']['destination']}) ---")
            print("  write:", r["operation"]["write_statement"])
            print("  decl :", r["destination_capacity_evidence"]["declaration_source_line"])
            print("  cap  :", r["destination_capacity_evidence"]["capacity_expression"],
                  "| width:", r["write_length"]["write_length_expression"])
            print("  guards:", r["enclosing_guards"][:4])
            print("  static:", r["reachability_evidence"]["function_storage_static"],
                  "| call_sites:", len(r["reachability_evidence"]["call_sites"]))
            shown += 1
    print(f"\nwritten {pkt_path}")
    print("NO labels assigned. Reviewers write study/stage1_labels.jsonl separately.")


if __name__ == "__main__":
    main()
