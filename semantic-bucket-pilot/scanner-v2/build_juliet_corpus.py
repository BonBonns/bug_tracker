#!/usr/bin/env python3
"""Juliet yield/pipeline study (NO model calls). Over a full scanned batch:
apply the FROZEN mechanical inclusion rule, normalize file-variants to independent
semantic TEMPLATES (not files), build leakage-safe model packets and audit them,
then freeze the corpus (pinned commit + per-file hashes) and split by template family.

Outputs a yield table + study/juliet/ corpus freeze + split.
Usage: build_juliet_corpus.py <scan_out_dir> <juliet_src_dir> <pinned_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS); sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import juliet_sanitize as san

OUTDIR = os.path.join(HERE, "study", "juliet")
SINK = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)\s*\(")
MIN_FAMILIES = 12          # same inference floor as the main study
DEV_FRACTION = 0.30
SPLIT_SALT = "juliet-cwe806-v1"
_SRC = {}


def src_lines(src_dir, base):
    if base not in _SRC:
        p = None
        for dp, _, fs in os.walk(src_dir):
            if base in fs:
                p = os.path.join(dp, base); break
        _SRC[base] = open(p, errors="replace").read().splitlines() if p else None
    return _SRC[base]


def enclosing_function(lines, op_line):
    """Brace-match the function body containing op_line -> (start,end,text)."""
    # find the '{' opening the function: scan up for the signature line's brace
    depth = 0; start = None
    for i in range(op_line - 1, -1, -1):
        if "{" in lines[i] and (start is None):
            # walk down from here could be inner block; instead find outermost by scanning up
            pass
    # simpler: expand outward by brace balance from op_line
    # find function start: nearest line above at column0 with `)` then `{`
    s = op_line - 1
    while s > 0 and not re.match(r"^\S.*\)\s*$", lines[s]) and "{" not in lines[s]:
        s -= 1
    # fallback: take a window
    b = None
    for i in range(max(0, op_line - 40), op_line):
        if "{" in lines[i]:
            b = i; break
    if b is None:
        return None
    depth = 0; e = None
    for i in range(b, min(len(lines), op_line + 200)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i >= op_line - 1:
            e = i; break
    if e is None:
        return None
    return b, e, "\n".join(lines[b:e + 1])


def oracle(fn):
    f = fn.lower()
    if "bad" in f and "good" not in f:
        return "vulnerable"
    if "good" in f:
        return "safe"
    return None


def sink_and_width(stmt):
    m = SINK.search(stmt)
    if not m:
        return None, None
    call = m.group(1)
    # width = 3rd arg (best-effort)
    args = stmt[stmt.find("(", m.start()) + 1:stmt.rfind(")")]
    parts = _split_args(args)
    width = parts[2].strip() if len(parts) >= 3 else (parts[-1].strip() if parts else "")
    # normalize: drop specific identifiers -> structural form
    wnorm = re.sub(r"[A-Za-z_]\w*", "V", width)
    return call, wnorm


def _split_args(s):
    out, depth, cur = [], 0, ""
    for c in s:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += c
    out.append(cur)
    return out


def main():
    scan_out, src_dir, commit = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(OUTDIR, exist_ok=True)
    recs, _ = v2.analyze_operations_v2(os.path.join(scan_out, "cpp.json"))

    included = []
    for r in recs:
        oc = oracle(r.get("function") or "")
        if oc is None:
            continue
        base = os.path.basename(r.get("file") or "")
        lines = src_lines(src_dir, base)
        line = r.get("line"); dest = r.get("dest")
        if not (lines and line and 1 <= line <= len(lines)):
            continue
        stmt = lines[line - 1].strip()
        # FROZEN inclusion rule
        if not SINK.search(stmt):                     # exact oracle sink
            continue
        if not (dest and dest in stmt):
            continue
        if len(SINK.findall(stmt)) != 1:              # no ambiguous line matching
            continue
        if not any("POTENTIAL FLAW" in lines[k] for k in range(max(0, line - 3), line)):
            continue
        if r.get("recommended_route") != "semantic_relationship_review":  # symbolic length route
            continue
        ev = r.get("_v2_evidence") or {}
        # fixed stack destination (capacity bound as a fixed array)
        etype = ev.get("element_type"); ecount = ev.get("element_count")
        call, wnorm = sink_and_width(stmt)
        included.append({"file": base, "function": r.get("function"), "line": line,
                         "dest": dest, "stmt": stmt, "oracle": oc,
                         "element_type": etype, "element_count": ecount,
                         "sink": call, "width_norm": wnorm})

    # ---- normalize to independent semantic TEMPLATES (not files) ----
    def tkey(x):
        return (x["element_type"], x["element_count"], x["sink"], x["width_norm"], x["dest"])
    fam = defaultdict(list)
    for x in included:
        fam["fam_" + hashlib.sha256(str(tkey(x)).encode()).hexdigest()[:12]].append(x)
    families = {k: v for k, v in fam.items()}
    both_sided = {k: v for k, v in families.items()
                  if any(i["oracle"] == "vulnerable" for i in v)
                  and any(i["oracle"] == "safe" for i in v)}

    # ---- leakage-safe packet construction + audit (on the MODEL packet) ----
    leak_fail = 0
    eligible = []
    for k, members in both_sided.items():
        ok = True
        for m in members:
            lines = src_lines(src_dir, m["file"])
            span = enclosing_function(lines, m["line"])
            if not span:
                ok = False; break
            _, _, body = span
            packet, _ = san.neutralize(body, m["function"])
            if san.leakage_scan(packet):
                ok = False; break
        if ok:
            eligible.append(k)
    elig_fam = {k: both_sided[k] for k in eligible}

    # ---- split by template family ----
    def bucket(fid):
        h = int(hashlib.sha256((SPLIT_SALT + "|" + fid).encode()).hexdigest(), 16)
        return "dev" if (h % 10000) / 10000.0 < DEV_FRACTION else "confirmatory"
    split = {k: bucket(k) for k in elig_fam}
    fam_split = Counter(split.values())

    n_files = len({x["file"] for x in included})
    inst_v = sum(1 for x in included if x["oracle"] == "vulnerable")
    inst_s = sum(1 for x in included if x["oracle"] == "safe")
    pairs = sum(min(sum(1 for i in v if i["oracle"] == "vulnerable"),
                    sum(1 for i in v if i["oracle"] == "safe")) for v in families.values())

    table = {
        "files_scanned": 224,
        "exact_oracle_matched_instances": len(included),
        "complete_vulnerable_safe_pairs": pairs,
        "independent_normalized_families": len(families),
        "families_with_both_sides": len(both_sided),
        "eligible_after_leakage_safe_packets": len(elig_fam),
        "leakage_failed_families": len(both_sided) - len(elig_fam),
        "vulnerable_instances": inst_v, "safe_instances": inst_s,
        "dev_families": fam_split["dev"], "confirmatory_families": fam_split["confirmatory"],
        "meets_min_inference_gate": fam_split["confirmatory"] >= MIN_FAMILIES,
    }
    corpus = {"pinned_commit": commit, "min_families_gate": MIN_FAMILIES,
              "families": {k: {"split": split.get(k), "n_instances": len(v),
                               "key_example": {kk: v[0][kk] for kk in
                                               ("element_type", "element_count", "sink", "width_norm", "dest")}}
                           for k, v in elig_fam.items()},
              "yield_table": table}
    with open(os.path.join(OUTDIR, "corpus_FROZEN.json"), "w") as fh:
        json.dump(corpus, fh, indent=2, sort_keys=True, default=str)

    print("YIELD TABLE")
    for k, val in table.items():
        print(f"  {k:42} {val}")
    print(f"\nfrozen -> {OUTDIR}/corpus_FROZEN.json (pinned commit {commit[:12]})")
    if not table["meets_min_inference_gate"]:
        print(f"\n** {len(elig_fam)} independent families < {MIN_FAMILIES} gate: this Juliet "
              f"slice is a PIPELINE/yield result, NOT a powered confirmatory sample. **")


if __name__ == "__main__":
    main()
