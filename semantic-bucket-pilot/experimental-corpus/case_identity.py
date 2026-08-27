#!/usr/bin/env python3
"""Experimental-case identity layer (SEPARATE from the frozen scanner corpus).

The frozen corpus counts one record per (program, recognized operation): that is
correct for the scanner boundary. But two DIFFERENT scanner inputs can contain
the SAME source function -- e.g. CVE-2019-11745 and CVE-2019-11759 both live in
lib/softoken/pkcs11c.c, so each scan ingests the whole file and both emit records
for `sftk_compute_ANSI_X9_63_kdf`. For the EXPERIMENT, identical code is one
case, not several. This layer folds the frozen llm_eligible records by code
identity so no experimental case is double-counted, and reports, per case,
whether the enclosing function actually differs between the vulnerable and
patched revisions (a real differential) or is incidental to the CVE.

It reads ONLY the frozen artifact (llm_eligible.jsonl) + the cached source; it
never re-runs or mutates the scanner. Output feeds ground-truth labelling and
case selection -- which remain downstream and must not consult experimental
condition B.
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = os.path.join(HERE, "..", "frozen-corpus", "llm_eligible.jsonl")

SRC = {"cve-2016-1950": "secasn1d.c", "cve-2019-17006": "rsapkcs.c",
       "cve-2019-11745": "pkcs11c.c", "cve-2019-11759": "pkcs11c.c",
       "mjpg-cve-huff": "jchuff.c"}


def function_body(src_file, fname):
    """Authoritative enclosing-function body by SIGNATURE match (K&R/C style:
    return type on its own line, `fname(` starting the next). Brace-balanced
    from the signature's opening brace to its matching close. Returns None if
    not found."""
    lines = open(src_file, errors="replace").read().split("\n")
    start = None
    for i, L in enumerate(lines):
        s = L.lstrip()
        if (s.startswith(fname + "(") or s.startswith(fname + " (")) and not s.startswith("*"):
            start = i
            break
    if start is None:
        return None
    body, depth, opened = [], 0, False
    for k in range(start, len(lines)):
        L = lines[k]
        body.append(L)
        depth += L.count("{") - L.count("}")
        if "{" in L:
            opened = True
        if opened and depth <= 0:
            break
    return "\n".join(body)


def body_hash(cve, side, fname):
    f = f"/tmp/{cve}/{side}/scan/work/csrc/{SRC[cve]}"
    if not os.path.exists(f):
        return None
    b = function_body(f, fname)
    return hashlib.sha256(b.encode()).hexdigest()[:12] if b else None


def build():
    recs = [json.loads(l) for l in open(FROZEN)]
    # group frozen records by their enclosing function's identity: the set of
    # (cve, patched-side body hash). Same function name + same patched body =
    # one case regardless of how many CVE files or write-lines it appears in.
    cases = {}
    for r in recs:
        cve = r["_source_label"].split("/")[0]
        fname = r["function"]
        ph = body_hash(cve, "patched", fname)
        vh = body_hash(cve, "vuln", fname)
        # case key folds cross-CVE copies of the identical patched body
        ckey = (fname, r.get("dest"), r["primary_reason_code"], ph)
        c = cases.setdefault(ckey, {
            "function": fname, "dest": r.get("dest"),
            "reason": r["primary_reason_code"],
            "bucket": r.get("uncertainty_bucket"),
            "route": r.get("recommended_route"),
            "patched_body_sha": ph, "vuln_body_sha": vh,
            "differential": (ph != vh),
            "seen_in_cves": set(), "sides": set(), "write_lines": set(),
            "n_frozen_records": 0})
        c["seen_in_cves"].add(cve)
        c["sides"].add(r["_side"])
        c["write_lines"].add((cve, r["_side"], r["line"]))
        c["n_frozen_records"] += 1
    # serialize
    out = []
    for c in cases.values():
        out.append({
            "function": c["function"], "dest": c["dest"], "reason": c["reason"],
            "uncertainty_bucket": c["bucket"], "recommended_route": c["route"],
            "seen_in_cves": sorted(c["seen_in_cves"]),
            "sides_present": sorted(c["sides"]),
            "vuln_patched_differential": c["differential"],
            "patched_body_sha": c["patched_body_sha"],
            "vuln_body_sha": c["vuln_body_sha"],
            "n_frozen_records": c["n_frozen_records"],
            "n_write_lines": len(c["write_lines"]),
        })
    out.sort(key=lambda x: (x["function"], str(x["dest"])))
    return recs, out


if __name__ == "__main__":
    recs, cases = build()
    with open(os.path.join(HERE, "case_identity.json"), "w") as fh:
        json.dump(cases, fh, indent=2, sort_keys=True)
    ndiff = sum(1 for c in cases if c["vuln_patched_differential"])
    print(f"frozen llm_eligible records : {len(recs)}")
    print(f"distinct experimental cases : {len(cases)}")
    print(f"vuln/patched differentials  : {ndiff}")
    print()
    for c in cases:
        diff = "DIFFERENTIAL" if c["vuln_patched_differential"] else "vuln==patched"
        print(f"{c['function']:28} {c['dest']:10} {c['reason']:34} "
              f"{diff:13} cves={c['seen_in_cves']} ({c['n_frozen_records']} recs)")
