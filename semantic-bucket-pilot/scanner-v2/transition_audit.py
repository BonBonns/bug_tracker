#!/usr/bin/env python3
"""Transition audit + backing-object validation for the single-object candidates.

Corrects the earlier overclaim. `sizeof(*dest)` / `sizeof(T)` proves the WRITE
LENGTH (one pointee), NOT that `dest` is backed by storage that large. A typed
pointer may be a parameter (backing in the caller), unresolved, offset, or
insufficiently backed. So a promotion is sound ONLY if the destination's backing
object and its capacity are separately established locally.

For every single-object candidate (v1 abstained with required_evidence_absent,
width is one sizeof with no multiplier) this records:
  v1_reason, new_evidence (write length), evidence_provenance, dest backing
  class, proposed v2 status, and whether the transition is SOUND.

Backing classes:
  stack_object          dest is a non-pointer local `T dest` -> capacity sizeof(T) locally. SOUND.
  local_alloc           dest is a local pointer assigned from alloc(sizeof(T))/&localT. SOUND.
  pointer_parameter     dest is a pointer parameter -> backing is the CALLER's. NOT locally established.
  unresolved_pointer    local pointer with no traced backing. NOT established.

Only stack_object / local_alloc are sound; the rest need caller/backing evidence
and MUST NOT be promoted. Reports exact counts (operations, functions, files,
case families) for the candidate set and the sound subset.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
_bfc = importlib.util.spec_from_file_location(
    "bfc", os.path.abspath(os.path.join(HERE, "..", "frozen-corpus", "build_frozen_corpus.py")))
build_frozen_corpus = importlib.util.module_from_spec(_bfc)
_bfc.loader.exec_module(build_frozen_corpus)
cfp = build_frozen_corpus._fingerprint
EXP = "/tmp/expansion"


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _b64(s):
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def load_params(scan_dir):
    """(method_id, name) set of parameters and {(mid,name): type}, from
    raw/parameters.tsv (cols: id, method_id, index, name, code, type, line)."""
    p = os.path.join(scan_dir, "raw", "parameters.tsv")
    params, ptypes = set(), {}
    if not os.path.exists(p):
        return params, ptypes
    for line in open(p, errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            try:
                mid, nm = int(f[1]), _b64(f[3])
                params.add((mid, nm))
                if len(f) >= 6:
                    ptypes[(mid, nm)] = _b64(f[5])
            except Exception:
                pass
    return params, ptypes


def _has_mult(w):
    s = re.sub(r"sizeof\s*\([^()]*\)", "SZ", str(w))
    s = re.sub(r"sizeof\s+\*?\s*[\w\[\].]+", "SZ", s)
    return any(o in s for o in ("*", "+", "-"))


def _sizeof_arg(w):
    w = str(w).strip()
    if _has_mult(w):
        return None
    m = re.match(r"^\s*sizeof\s*(\(\s*(?P<p>[^()]*)\s*\)|\s+(?P<b>[*]?\s*[\w\[\].]+))\s*$", w)
    if not m:
        return None
    return (m.group("p") if m.group("p") is not None else m.group("b")).strip()


def classify_backing(d, params, param_types, method_ids, dest, alloc_targets):
    """Return (backing_class, dest_type, provenance). params: {(mid,name)};
    param_types: {(mid,name): type_full_name}."""
    # parameter first (params are NOT in `locals`)
    is_param = any((mid, dest) in params for mid in method_ids)
    if is_param:
        pt = next((param_types.get((mid, dest)) for mid in method_ids
                   if (mid, dest) in param_types), None)
        return "pointer_parameter", pt, "declared as a function parameter (backing is the caller's)"
    # local declaration
    decl = None
    for l in d.get("locals", []):
        if l.get("name") == dest and l.get("method_id") in method_ids:
            decl = l
            break
    dest_type = (decl or {}).get("type_full_name")
    is_ptr = bool(dest_type and dest_type.strip().endswith("*"))
    if decl and not is_ptr:
        return "stack_object", dest_type, f"local object `{decl.get('code')}`"
    if is_ptr and any((mid, dest) in alloc_targets for mid in method_ids):
        return "local_alloc", dest_type, "local pointer assigned from an allocation"
    return "unresolved_pointer", dest_type, "pointer with no locally-traced backing"


def audit():
    rc = _load("oob_runtime_capacity_verdict")
    candidates = []
    for fid in sorted(os.listdir(EXP)):
        for side in ("vuln", "patched"):
            scan_dir = os.path.join(EXP, fid, side)
            p = os.path.join(scan_dir, "cpp.json")
            if not os.path.exists(p):
                continue
            d = json.load(open(p))
            params, param_types = load_params(scan_dir)
            # allocation targets: local ids that are assigned from an alloc-ish call
            alloc_targets = set()
            calls_by_line = defaultdict(list)
            for c in d.get("calls", []):
                calls_by_line[(c.get("function_id"), c.get("line"))].append(c.get("code") or "")
            fn_by_name = defaultdict(set)
            for f in d.get("functions", []):
                fn_by_name[f.get("full_name")].add(f.get("id"))
            local_name_by_id = {l.get("id"): (l.get("method_id"), l.get("name"))
                                for l in d.get("locals", [])}
            for a in d.get("assignments", []):
                tgt = a.get("target_local_id")
                deriv = (a.get("derivation") or "")
                if tgt in local_name_by_id and re.search(r"alloc|malloc|calloc", str(deriv), re.I):
                    alloc_targets.add(local_name_by_id[tgt])
            label = f"{fid}/{side}"
            for r in rc.analyze_operations(p):
                if r.get("analysis_status") != "abstained":
                    continue
                if (r.get("primary_reason_code") or r.get("reason_code")) != "required_evidence_absent":
                    continue
                arg = _sizeof_arg(r.get("width_expr"))
                if arg is None:
                    continue
                dest = r.get("dest")
                a = arg.replace(" ", "")
                form = None
                if dest and (a == "*" + dest or a == dest + "[0]" or a == "*" + dest):
                    form = "sizeof(*dest)"
                else:
                    form = "sizeof(TYPE)"
                mids = fn_by_name.get(r.get("function"), set())
                backing, dest_type, prov = classify_backing(d, params, param_types, mids, dest, alloc_targets)
                sound = backing in ("stack_object", "local_alloc")
                r["_source_label"] = label
                candidates.append({
                    "operation_fingerprint": cfp(r),
                    "case_family_id": "cf_" + hashlib.sha256(
                        "|".join([fid, str(r.get("file")), str(r.get("function")), str(dest)]).encode()
                    ).hexdigest()[:16],
                    "source": label, "file": r.get("file"), "function": r.get("function"),
                    "line": r.get("line"), "dest": dest, "form": form,
                    "width_expr": r.get("width_expr"), "sizeof_arg": arg,
                    "dest_type": dest_type, "backing_class": backing,
                    "v1_reason": "required_evidence_absent",
                    "new_evidence": f"write length = one pointee object ({form})",
                    "evidence_provenance": f"width_expr + {prov}",
                    "proposed_v2": "deterministic_complete" if sound else "NO PROMOTION (backing unestablished)",
                    "sound": sound,
                })
    return candidates


def counts(rows):
    dfp = {r["operation_fingerprint"] for r in rows}
    return {
        "distinct_operations": len(dfp),
        "distinct_functions": len({(r["source"].split("/")[0], r["function"]) for r in rows}),
        "distinct_function_names": len({r["function"] for r in rows}),
        "distinct_source_files": len({r["file"] for r in rows}),
        "case_families": len({r["case_family_id"] for r in rows}),
    }


def main():
    rows = audit()
    # dedup by operation fingerprint (keep first)
    seen, dedup = set(), []
    for r in rows:
        if r["operation_fingerprint"] in seen:
            continue
        seen.add(r["operation_fingerprint"])
        dedup.append(r)
    sound = [r for r in dedup if r["sound"]]
    unsound = [r for r in dedup if not r["sound"]]
    from collections import Counter
    report = {
        "candidate_set_counts": counts(dedup),
        "sound_subset_counts": counts(sound),
        "by_backing_class": dict(Counter(r["backing_class"] for r in dedup)),
        "by_backing_class_sound": dict(Counter(r["backing_class"] for r in sound)),
        "transitions": dedup,
    }
    with open(os.path.join(HERE, "transition_audit.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
    print("SINGLE-OBJECT CANDIDATE SET (exact):", json.dumps(report["candidate_set_counts"]))
    print("by backing class:", report["by_backing_class"])
    print("SOUND subset (backing established locally):", json.dumps(report["sound_subset_counts"]))
    print("sound by backing class:", report["by_backing_class_sound"])
    print(f"\ncandidates: {len(dedup)}  sound: {len(sound)}  unsound-as-promoted: {len(unsound)}")
    print("\nsample UNSOUND (would have been wrongly promoted):")
    for r in unsound[:8]:
        print(f"   {r['source']:12} {r['function']}:{r['line']} dest={r['dest']} "
              f"[{r['backing_class']}] {r['form']} type={r['dest_type']}")
    print("\nsample SOUND:")
    for r in sound[:8]:
        print(f"   {r['source']:12} {r['function']}:{r['line']} dest={r['dest']} "
              f"[{r['backing_class']}] {r['form']} type={r['dest_type']}")


if __name__ == "__main__":
    main()
