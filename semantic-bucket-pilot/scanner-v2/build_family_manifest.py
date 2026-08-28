#!/usr/bin/env python3
"""Capability-effect accuracy study — STAGE 0 (manifest only, NO LLM runs).

TWO LEVELS (corrected):
  * case INSTANCE = one operation in one source revision (vuln OR patched). Ground
    truth and A/B/C responses are assigned here. Exact duplicates of the SAME
    revision+site across the E2/E4 scans collapse to one instance; vulnerable and
    patched revisions are ALWAYS separate instances (their security meaning can
    differ even when the write statement is textually identical).
  * case FAMILY = correlated instances of the same logical site across
    vulnerable/patched revisions and duplicate scans. Used ONLY for the dev/
    confirmatory split and for statistical clustering — never for labeling, and a
    family is NEVER split after labels are seen.

Vuln<->patched ordinal pairing is VERIFIED with source anchors: a family whose
content-group has one write per side pairs unambiguously; a multi-write family is
verified only if the ordinal-aligned vuln/patched write statements match by source
text. Families that cannot be verified are EXCLUDED from the confirmatory set
(kept in the manifest, usable for development), not guessed.

Outputs under scanner-v2/study/:
  instances.jsonl   one immutable row per case instance (id, revision/side, member
                    op_ids, source anchor) — no model output, no label.
  families.json     family_id -> member instance_ids, key, span, pairing verdict, split.
  split.json        family_id -> {dev|confirmatory|excluded_unverified}.
  FROZEN.json       sha256 of each frozen artifact + parameters.
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
FROZEN = os.path.join(REPO, "semantic-bucket-pilot", "frozen-corpus")

_spec = importlib.util.spec_from_file_location(
    "build_frozen_corpus", os.path.join(FROZEN, "build_frozen_corpus.py"))
bfc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bfc)

EXP = "/tmp/expansion"
DEV_FRACTION = 0.30
SPLIT_SALT = "capeffect-498-v2"     # v2 = two-level instance/family correction


# ---------------------------------------------------------------- source anchors
_FILE_CACHE = {}
_BODY_CACHE = {}


def _file_lines(scan_side, relpath):
    key = (scan_side, relpath)
    if key not in _FILE_CACHE:
        p = os.path.join(EXP, scan_side, "csrc", relpath)
        try:
            _FILE_CACHE[key] = open(p, errors="replace").read().splitlines()
        except OSError:
            _FILE_CACHE[key] = None
    return _FILE_CACHE[key]


def stmt_text(op):
    lines = _file_lines(op["source_label"], op["file"])
    if not lines or not (1 <= op["line"] <= len(lines)):
        return None
    return lines[op["line"] - 1].strip()


def func_body_sha(op):
    """sha256 of the enclosing function's whitespace-normalized source — the
    'same revision at this site' test for collapsing E2/E4 duplicates."""
    key = (op["source_label"], op["file"], op["function"], op["line"])
    if key in _BODY_CACHE:
        return _BODY_CACHE[key]
    lines = _file_lines(op["source_label"], op["file"])
    val = None
    if lines:
        txt = "\n".join(lines)
        fn = norm_function(op["function"])
        for m in re.finditer(r"\b" + re.escape(fn) + r"\s*\(", txt):
            b = txt.find("{", m.end())
            if b < 0 or b - m.end() > 400:
                continue
            depth, i, n = 0, b, len(txt)
            while i < n:
                c = txt[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = txt[b:i + 1]
            # the body that actually contains this op's line
            start_line = txt.count("\n", 0, b) + 1
            end_line = txt.count("\n", 0, i) + 1
            if start_line <= op["line"] <= end_line:
                norm = re.sub(r"\s+", " ", body).strip()
                val = hashlib.sha256(norm.encode()).hexdigest()[:16]
                break
    _BODY_CACHE[key] = val
    return val


# ---------------------------------------------------------------- keys
def norm_function(fn):
    return re.sub(r"<[^>]*>\d*", "", fn or "")


def content_key(op):
    return (op["file"], norm_function(op["function"]), op["dest"],
            op["element_type"], op["element_count"], op["capacity_expr"], op["width_expr"])


def side_of(op):
    return op["source_label"].split("/")[1]      # repo layout token: vuln | patched


# The repository side is NOT the security class. "vuln"/"patched" name which
# revision the file came from; whether THIS operation is actually vulnerable or safe
# is a Stage-1 label established independently. Report revision side as pre/post-patch.
REV_NAME = {"vuln": "pre_patch", "patched": "post_patch"}


def revision_name(op):
    return REV_NAME[side_of(op)]


def scan_of(op):
    return op["source_label"].split("/")[0]      # E1 | E2 | E4


def fam_id(key):
    return "fam_" + hashlib.sha256("|".join(str(x) for x in key).encode()).hexdigest()[:12]


# ---------------------------------------------------------------- family clustering
def assign_family_keys(ops):
    """Cluster into logical sites. content_key + ordinal of the write among
    same-content writes within one (scan,side), ordered by line. Copies collapse;
    distinct sites never merge. If a content-group's write-count differs across
    scans (E2 vs E4 coverage), do not merge across scans for that group."""
    by_content_ss = defaultdict(lambda: defaultdict(list))
    for o in ops:
        by_content_ss[content_key(o)][o["source_label"]].append(o)
    key_of = {}
    multiplicity = {}       # content_key -> max writes per (scan,side)
    for ck, ss_map in by_content_ss.items():
        per_scan_counts = defaultdict(set)
        for ss, members in ss_map.items():
            per_scan_counts[ss.split("/")[0]].add(len(members))
        consistent = (all(len(cs) == 1 for cs in per_scan_counts.values())
                      and len({next(iter(cs)) for cs in per_scan_counts.values()}) == 1)
        multiplicity[ck] = max((len(m) for m in ss_map.values()), default=1)
        for ss, members in ss_map.items():
            for i, o in enumerate(sorted(members, key=lambda m: m["line"])):
                key_of[o["op_id"]] = (ck, i) if consistent else (ck, ss.split("/")[0], i)
    return key_of, multiplicity


# ---------------------------------------------------------------- pairing verification
def verify_pairing(members, multiplicity):
    """Within one family, confirm vuln and patched members are the SAME site.
    - multiplicity 1  -> unambiguous (only one same-content write per side).
    - multiplicity >1 -> require the ordinal-aligned vuln/patched write statements
      to match by source text within each scan; else 'unverified'."""
    ck = content_key(members[0])
    if multiplicity.get(ck, 1) == 1:
        return "unambiguous_single_write", True
    # multi-write: group this family's members by scan, compare stmt text across sides
    ok = True
    checked = False
    by_scan = defaultdict(dict)   # scan -> side -> op
    for m in members:
        by_scan[scan_of(m)][side_of(m)] = m
    for scan, sides in by_scan.items():
        if "vuln" in sides and "patched" in sides:
            checked = True
            if stmt_text(sides["vuln"]) != stmt_text(sides["patched"]):
                ok = False
    if not checked:
        return "single_side_only", False        # cannot confirm the pair -> exclude
    return ("stmt_anchor_matched", True) if ok else ("stmt_anchor_mismatch", False)


def split_bucket(family_id):
    h = int(hashlib.sha256((SPLIT_SALT + "|" + family_id).encode()).hexdigest(), 16)
    return "dev" if (h % 10000) / 10000.0 < DEV_FRACTION else "confirmatory"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# ---------------------------------------------------------------- main
def main():
    os.makedirs(OUT, exist_ok=True)
    # Op list is the frozen, already-audited 498 (matches the transition-matrix set).
    ops = [json.loads(l) for l in open(os.path.join(OUT, "study_manifest.jsonl"))]
    tm = json.load(open(os.path.join(HERE, "transition_matrix_v1_v2.json")))
    tm_sem = {c["fp"] for c in tm["changed"] if c["to"] == "semantic_relationship_review"}
    assert {o["op_id"] for o in ops} == tm_sem and len(ops) == 498, "498 op set drifted"

    key_of, multiplicity = assign_family_keys(ops)
    fam_members = defaultdict(list)
    for o in ops:
        fam_members[fam_id(key_of[o["op_id"]])].append(o)

    # over-merge guard (a family must not hold >1 line within one scan/side)
    for members in fam_members.values():
        seen = defaultdict(set)
        for m in members:
            seen[m["source_label"]].add(m["line"])
        assert all(len(v) == 1 for v in seen.values()), "family over-merges distinct sites"

    # ---- instances: collapse exact same-revision E2/E4 duplicates within family+side
    inst_of = {}                       # op_id -> instance_id
    inst_members = defaultdict(list)   # instance_id -> [op...]
    for fmid, members in fam_members.items():
        for m in members:
            fbsha = func_body_sha(m) or f"nobody:{m['line']}"
            iid = "inst_" + hashlib.sha256(f"{fmid}|{side_of(m)}|{fbsha}".encode()).hexdigest()[:12]
            inst_of[m["op_id"]] = iid
            inst_members[iid].append(m)

    # ---- family records + pairing verification + split
    fam_records = {}
    for fmid, members in sorted(fam_members.items()):
        verdict, verified = verify_pairing(members, multiplicity)
        iids = sorted({inst_of[m["op_id"]] for m in members})
        sides = sorted({revision_name(m) for m in members})
        base = split_bucket(fmid)
        split = base if verified else "excluded_unverified"
        fam_records[fmid] = {
            "family_id": fmid,
            "n_operations": len(members),
            "n_instances": len(iids),
            "instance_ids": iids,
            "sides": sides,
            "content_multiplicity": multiplicity.get(content_key(members[0]), 1),
            "pairing_verdict": verdict,
            "pairing_verified": verified,
            "key": {"file": members[0]["file"], "function": norm_function(members[0]["function"]),
                    "dest": members[0]["dest"], "width_expr": members[0]["width_expr"],
                    "capacity_expr": members[0]["capacity_expr"]},
            "spans_scan_sides": sorted({m["source_label"] for m in members}),
            "split": split,
        }

    # ---- instance records (labeling unit; NO label, NO model output)
    inst_records = {}
    for iid, members in inst_members.items():
        rep = sorted(members, key=lambda m: (m["source_label"], m["line"]))[0]
        fmid = fam_id(key_of[rep["op_id"]])
        inst_records[iid] = {
            "instance_id": iid,
            "family_id": fmid,
            "revision_side": revision_name(rep),   # pre_patch | post_patch (repo side, NOT security class)
            "op_ids": sorted(m["op_id"] for m in members),
            "collapsed_scans": sorted({scan_of(m) for m in members}),
            "file": rep["file"], "function": norm_function(rep["function"]),
            "dest": rep["dest"], "line_by_scan": {m["source_label"]: m["line"] for m in members},
            "width_expr": rep["width_expr"], "capacity_expr": rep["capacity_expr"],
            "element_type": rep["element_type"], "element_count": rep["element_count"],
            "unresolved_property": rep["unresolved_property"],
            "write_stmt": stmt_text(rep),
            "split": fam_records[fmid]["split"],
            # NO label field here. Stage-1 labels live in a SEPARATE sidecar
            # (study/stage1_labels.jsonl), joined by instance_id, and are frozen
            # separately after review. A frozen Stage-0 artifact is never mutated
            # to carry Stage-1 results.
        }

    # ---- write frozen artifacts
    inst_path = os.path.join(OUT, "instances.jsonl")
    with open(inst_path, "w") as fh:
        for iid in sorted(inst_records):
            fh.write(json.dumps(inst_records[iid], sort_keys=True) + "\n")
    fam_path = os.path.join(OUT, "families.json")
    with open(fam_path, "w") as fh:
        json.dump({"families": fam_records, "count": len(fam_records)}, fh, indent=2, sort_keys=True)
    split_path = os.path.join(OUT, "split.json")
    with open(split_path, "w") as fh:
        json.dump({"salt": SPLIT_SALT, "dev_fraction": DEV_FRACTION, "by": "family",
                   "assignment": {k: v["split"] for k, v in fam_records.items()}},
                  fh, indent=2, sort_keys=True)

    # ---- tallies
    fam_split = Counter(f["split"] for f in fam_records.values())
    inst_split = Counter(i["split"] for i in inst_records.values())
    inst_by_side = Counter(i["revision_side"] for i in inst_records.values())
    conf_inst_by_side = Counter(i["revision_side"] for i in inst_records.values()
                                if i["split"] == "confirmatory")
    fam_inst_hist = dict(sorted(Counter(f["n_instances"] for f in fam_records.values()).items()))
    multi = sum(1 for f in fam_records.values() if f["content_multiplicity"] > 1)

    frozen = {
        "study": "capability-effect accuracy — target = 498 newly LLM-eligible operations",
        "stage": "0 (two-level manifest/family/split — NO LLM, NO labels)",
        "operations": len(ops),
        "families": len(fam_records),
        "instances": len(inst_records),
        "instances_by_side": dict(inst_by_side),
        "families_multi_write": multi,
        "pairing": dict(Counter(f["pairing_verdict"] for f in fam_records.values())),
        "split_families": dict(fam_split),
        "split_instances": dict(inst_split),
        "confirmatory_instances_by_side": dict(conf_inst_by_side),
        "artifacts_sha256": {os.path.basename(p): sha256_file(p)
                             for p in (os.path.join(OUT, "study_manifest.jsonl"),
                                       inst_path, fam_path, split_path)},
        "split_params": {"salt": SPLIT_SALT, "dev_fraction": DEV_FRACTION},
    }
    with open(os.path.join(OUT, "FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True)

    # leakage check
    assert not (set(f for f, r in fam_records.items() if r["split"] == "dev")
                & set(f for f, r in fam_records.items() if r["split"] == "confirmatory"))

    print(f"operations                     : {len(ops)}")
    print(f"case FAMILIES (clusters)       : {len(fam_records)}   [over-merge asserted 0]")
    print(f"  instances-per-family hist    : {fam_inst_hist}")
    print(f"  multi-write families         : {multi}")
    print(f"case INSTANCES (label units)   : {len(inst_records)}   by revision side {dict(inst_by_side)}")
    print(f"  (revision side = repo layout, NOT security class; labels are Stage 1)")
    print(f"pairing verification           : {dict(Counter(f['pairing_verdict'] for f in fam_records.values()))}")
    print(f"\nsplit BY FAMILY (dev_fraction={DEV_FRACTION}):")
    print(f"  families     : {dict(fam_split)}")
    print(f"  instances    : {dict(inst_split)}")
    print(f"  confirmatory instances by revision side : {dict(conf_inst_by_side)}")
    print(f"\nCLUSTERS (families) in confirmatory = {fam_split['confirmatory']}")
    print(f"LABELED UNITS (instances) in confirmatory = {inst_split['confirmatory']}")
    print(f"EXCLUDED unverified families = {fam_split['excluded_unverified']} "
          f"({inst_split['excluded_unverified']} instances)")
    print(f"\nartifacts under {OUT}/ ; FROZEN.json records sha256. NO LLM, NO labels.")


if __name__ == "__main__":
    main()
