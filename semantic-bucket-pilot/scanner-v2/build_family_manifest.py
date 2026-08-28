#!/usr/bin/env python3
"""Capability-effect accuracy study — STAGE 0 (manifest only, NO LLM runs).

Builds and audits the study manifest for the 498 operations the stack-capacity
capability newly made LLM-eligible (v1 additional_evidence_required -> v2
semantic_relationship_review), collapses them into independent case families,
freezes a by-family development / confirmatory split, and writes immutable IDs +
content hashes. It emits NO model outputs and makes NO outcome labels — those come
later, independently and blinded (see ACCURACY_STUDY_PROTOCOL.md).

Outputs (all under scanner-v2/study/):
  study_manifest.jsonl   one immutable row per operation (id, location, fingerprint,
                         evidence) — no model output, no label.
  families.json          family_id -> member op_ids, family key, span (scans/sides/lines).
  split.json             family_id -> {dev|confirmatory}, deterministic by hash.
  FROZEN.json            sha256 of each frozen artifact + parameters, the freeze record.
"""
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study")
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.path.join(REPO, "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
FROZEN = os.path.join(REPO, "semantic-bucket-pilot", "frozen-corpus")
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)

_spec = importlib.util.spec_from_file_location(
    "build_frozen_corpus", os.path.join(FROZEN, "build_frozen_corpus.py"))
bfc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bfc)
_fingerprint = bfc._fingerprint          # immutable operation id (frozen)

import oob_runtime_capacity_v2 as v2

EXP = "/tmp/expansion"
DEV_FRACTION = 0.30                        # pre-registered; by FAMILY, not operation
SPLIT_SALT = "capeffect-498-v1"            # fixes the deterministic split forever


def collect_498():
    """Re-derive the 498 semantic promotions directly from v2 over the 10 scans."""
    ops = []
    for fid in sorted(os.listdir(EXP)):
        for side in ("vuln", "patched"):
            p = os.path.join(EXP, fid, side, "cpp.json")
            if not os.path.exists(p):
                continue
            label = f"{fid}/{side}"
            recs, _ = v2.analyze_operations_v2(p)
            for r in recs:
                if (r.get("_v2_disposition") == "relationship_unresolved"
                        and r.get("recommended_route") == "semantic_relationship_review"):
                    r["_source_label"] = label
                    ev = r.get("_v2_evidence", {})
                    op_id = _fingerprint(r)   # uses _source_label|file|function|line|dest
                    ops.append({
                        "op_id": op_id,
                        "source_label": label,
                        "file": r.get("file"),
                        "function": r.get("function"),
                        "line": r.get("line"),
                        "dest": r.get("dest"),
                        "width_expr": r.get("width_expr") or ev.get("width"),
                        "element_type": ev.get("element_type"),
                        "element_count": ev.get("element_count"),
                        "capacity_expr": ev.get("capacity_expr"),
                        "unresolved_property": r.get("unresolved_property"),
                        "recommended_route": r.get("recommended_route"),
                        "v1_route": "additional_evidence_required",
                    })
    return ops


def norm_function(fn):
    # strip Joern duplicate/lambda markers so TLS_P_hash<duplicate>0 == TLS_P_hash
    return re.sub(r"<[^>]*>\d*", "", fn or "")


def content_key(op):
    return (op["file"], norm_function(op["function"]), op["dest"],
            op["element_type"], op["element_count"], op["capacity_expr"], op["width_expr"])


def family_key(op, with_line):
    k = content_key(op)
    if with_line:
        k = k + (op["line"],)
    return k


def scan_family(op):
    return op["source_label"].split("/")[0]   # E1 / E2 / E4


def assign_ordinals(ops):
    """PRIMARY family key = content_key + ordinal of the write among same-content
    writes within one (scan,side), ordered by line. This collapses copies of the
    SAME operation across scans/sides/vuln-patched (the k-th write matches the k-th,
    regardless of absolute line, so a patch that shifts lines does not split a pair)
    while keeping DISTINCT call sites (different ordinals) in separate families.

    Guard: if a content-group has a DIFFERENT number of same-content writes across
    expansion scans (E2 vs E4 captured different coverage), cross-scan ordinal
    alignment is not 1:1, so for that group only we DO NOT merge across scans — the
    scan family is added to the key (vuln/patched, always consistent, still merge).
    Returns {op_id: family_key} and the per-content consistency map."""
    by_content_ss = defaultdict(lambda: defaultdict(list))
    for o in ops:
        by_content_ss[content_key(o)][o["source_label"]].append(o)
    key_of = {}
    consistency = {}
    for ck, ss_map in by_content_ss.items():
        # count writes per SCAN (collapsing vuln/patched, which always agree)
        per_scan = defaultdict(set)
        for ss, members in ss_map.items():
            per_scan[ss.split("/")[0]].add(len(members))
        cross_scan_counts = {sf: next(iter(cs)) for sf, cs in per_scan.items()}
        consistent = len(set(cross_scan_counts.values())) == 1 and all(len(cs) == 1 for cs in per_scan.values())
        consistency[ck] = consistent
        for ss, members in ss_map.items():
            for i, o in enumerate(sorted(members, key=lambda m: m["line"])):
                if consistent:
                    key_of[o["op_id"]] = (ck, i)
                else:
                    key_of[o["op_id"]] = (ck, scan_family(o), i)   # no cross-scan merge
    return key_of, consistency


def fam_id(key):
    return "fam_" + hashlib.sha256("|".join(str(x) for x in key).encode()).hexdigest()[:12]


def size_hist(sizes):
    return dict(sorted(Counter(sizes).items()))


def split_bucket(family_id):
    h = int(hashlib.sha256((SPLIT_SALT + "|" + family_id).encode()).hexdigest(), 16)
    return "dev" if (h % 10000) / 10000.0 < DEV_FRACTION else "confirmatory"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    os.makedirs(OUT, exist_ok=True)
    ops = collect_498()

    # audit: count + distinct ids, cross-check against the transition matrix set
    assert len({o["op_id"] for o in ops}) == len(ops), "op_id (fingerprint) collision in the 498"
    tm = json.load(open(os.path.join(HERE, "transition_matrix_v1_v2.json")))
    tm_sem = {c["fp"] for c in tm["changed"] if c["to"] == "semantic_relationship_review"}
    ids = {o["op_id"] for o in ops}
    assert ids == tm_sem, (
        f"manifest set != transition-matrix semantic set "
        f"(manifest {len(ids)}, tm {len(tm_sem)}, sym-diff {len(ids ^ tm_sem)})")
    n = len(ops)

    # ---- families ----
    # PRIMARY: content-key + ordinal-within-(scan,side) (collapses copies, never
    # merges distinct call sites). Two SENSITIVITY variants reported alongside:
    #   content-only  -> lower bound on family count (over-merges distinct sites)
    #   content+line  -> upper bound (may split line-shifted vuln/patched pairs)
    key_of, consistency = assign_ordinals(ops)
    prim = defaultdict(list)
    for o in ops:
        prim[fam_id(key_of[o["op_id"]])].append(o)

    content_only = defaultdict(list)
    altf = defaultdict(list)
    for o in ops:
        content_only[fam_id(family_key(o, False))].append(o)
        altf[fam_id(family_key(o, True))].append(o)

    # audit the PRIMARY key: no family may contain >1 line within one (scan,side)
    overmerge = 0
    for members in prim.values():
        by_ss = defaultdict(set)
        for m in members:
            by_ss[m["source_label"]].add(m["line"])
        if any(len(ls) > 1 for ls in by_ss.values()):
            overmerge += 1
    assert overmerge == 0, f"PRIMARY (ordinal) key still over-merges {overmerge} families"

    # how many content-groups have inconsistent write-counts across scan/sides
    # (where ordinal alignment is an approximation, flagged for label-time review)?
    inconsistent = [ck for ck, ok in consistency.items() if not ok]

    prim_sizes = [len(v) for v in prim.values()]
    alt_sizes = [len(v) for v in altf.values()]
    content_only_sizes = [len(v) for v in content_only.values()]

    # ---- freeze split by PRIMARY family ----
    fam_records = {}
    for fmid, members in sorted(prim.items()):
        sides = sorted({m["source_label"] for m in members})
        lines = sorted({m["line"] for m in members})
        rep = sorted(members, key=lambda m: (m["source_label"], m["line"]))[0]
        fkey = key_of[members[0]["op_id"]]
        ck, ordinal = fkey[0], fkey[-1]
        fam_records[fmid] = {
            "family_id": fmid,
            "size": len(members),
            "op_ids": sorted(m["op_id"] for m in members),
            "representative_op_id": rep["op_id"],
            "site_ordinal": ordinal,
            "key": {"file": members[0]["file"], "function": norm_function(members[0]["function"]),
                    "dest": members[0]["dest"], "element_type": members[0]["element_type"],
                    "element_count": members[0]["element_count"],
                    "capacity_expr": members[0]["capacity_expr"],
                    "width_expr": members[0]["width_expr"]},
            "spans_scan_sides": sides,
            "spans_lines": lines,
            "write_count_consistent_across_sides": consistency[ck],
            "split": split_bucket(fmid),
        }
    split_counts = Counter(f["split"] for f in fam_records.values())
    op_split = Counter()
    for f in fam_records.values():
        op_split[f["split"]] += f["size"]

    # ---- write frozen artifacts (no model output, no label) ----
    man_path = os.path.join(OUT, "study_manifest.jsonl")
    with open(man_path, "w") as fh:
        for o in sorted(ops, key=lambda x: x["op_id"]):
            fh.write(json.dumps(o, sort_keys=True) + "\n")
    fam_path = os.path.join(OUT, "families.json")
    with open(fam_path, "w") as fh:
        json.dump({"families": fam_records,
                   "primary_key": "content_key(file|function(norm)|dest|element_type|element_count|capacity_expr|width_expr) + site_ordinal within (scan,side)",
                   "count": len(fam_records),
                   "sensitivity": {"content_only_families": len(content_only),
                                   "content_plus_line_families": len(altf)},
                   "write_count_inconsistent_content_groups": len(inconsistent)},
                  fh, indent=2, sort_keys=True)
    split_path = os.path.join(OUT, "split.json")
    with open(split_path, "w") as fh:
        json.dump({"salt": SPLIT_SALT, "dev_fraction": DEV_FRACTION,
                   "by": "family (never operation)",
                   "assignment": {k: v["split"] for k, v in fam_records.items()}},
                  fh, indent=2, sort_keys=True)

    frozen = {
        "study": "capability-effect accuracy — target population = 498 newly LLM-eligible operations",
        "stage": "0 (manifest/family/split only — NO LLM conditions run, NO outcome labels)",
        "operations": n,
        "families_primary_ordinal": len(prim),
        "families_content_only_lowerbound": len(content_only),
        "families_content_plus_line_upperbound": len(altf),
        "write_count_inconsistent_content_groups": len(inconsistent),
        "split": {"dev_families": split_counts["dev"], "confirmatory_families": split_counts["confirmatory"],
                  "dev_operations": op_split["dev"], "confirmatory_operations": op_split["confirmatory"]},
        "artifacts_sha256": {os.path.basename(p): sha256_file(p)
                             for p in (man_path, fam_path, split_path)},
        "split_params": {"salt": SPLIT_SALT, "dev_fraction": DEV_FRACTION},
    }
    with open(os.path.join(OUT, "FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True)

    # ---- report ----
    print(f"operations (498 target)              : {n}")
    print(f"PRIMARY families (content + ordinal) : {len(prim)}   [over-merge check: 0, asserted]")
    print(f"  size distribution (size->count)    : {size_hist(prim_sizes)}")
    print(f"  largest families                   : "
          f"{sorted(((len(v), fam_records[k]['key']['function'], fam_records[k]['key']['dest']) for k,v in prim.items()), reverse=True)[:6]}")
    print(f"sensitivity — content-only (lower)   : {len(content_only)} families   dist {size_hist(content_only_sizes)}")
    print(f"sensitivity — content+line (upper)   : {len(altf)} families   dist {size_hist(alt_sizes)}")
    print(f"content-groups w/ inconsistent write-count across sides (ordinal approx flagged): {len(inconsistent)}")
    print(f"\nFROZEN split (by PRIMARY family, dev_fraction={DEV_FRACTION}):")
    print(f"  dev          : {split_counts['dev']} families / {op_split['dev']} ops")
    print(f"  confirmatory : {split_counts['confirmatory']} families / {op_split['confirmatory']} ops")
    print(f"\nindependent sample size (families) = {len(prim)}  <-- the real n for the confirmatory test")
    print(f"artifacts written under {OUT}/ ; FROZEN.json records sha256 of each.")
    print("NO LLM condition was run; NO outcome label was assigned.")


if __name__ == "__main__":
    main()
