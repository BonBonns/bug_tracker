#!/usr/bin/env python3
"""Deterministic SecVulEval held-out freeze (NO model calls, NO TChecker, NO manual
per-site interpretation). Implements the two rules the confirmatory design requires,
BEFORE any capability runs:

  RULE 1 - exact write-site mapping: map the external labeled/fix statement to a UNIQUE
           destination WRITE / index operation, purely from source text. Each site is
           mapped / ambiguous / no_write_found; only `mapped` sites enter scoring.
  RULE 2 - family assignment: a deterministic family id from source / proof-obligation
           STRUCTURE only (write kind x dest shape x length shape), frozen now; never
           recomputed after any scanner output is seen.

Applied to whatever SecVulEval data is reachable (the repo's random_subset.json; the full
HuggingFace dataset is proxy-blocked in this environment). Magma-overlap projects and
duplicate sites are removed. Emits a frozen manifest with hashes and class/family counts.

Usage: secvuleval_freeze.py <random_subset.json> <pinned_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict

INCLUDE_CWE = {"CWE-787", "CWE-122", "CWE-120"}     # OOB write / heap overflow / buffer-copy overflow
AMBIGUOUS_CWE = {"CWE-119"}                          # read-or-write ambiguous -> excluded
MAGMA_PROJECTS = {"libpng", "libsndfile", "libtiff", "libxml2", "lua", "openssl",
                  "php", "php-src", "poppler", "sqlite3", "sqlite"}

COPY = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|strlcpy|strcat|strncat|strlcat|"
                  r"sprintf|snprintf|vsnprintf|vsprintf|bcopy|memset|wmemcpy|wcscpy|wcsncpy)\s*\(")
IDXW = re.compile(r"([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*\[[^\]\n]+\]\s*=(?!=)")
DEREFW = re.compile(r"\*\s*\(?\s*([A-Za-z_][\w.\->\[\] ]*?)\s*\)?\s*=(?!=)")
WINDOW = 3   # frozen: a write must be within +-WINDOW source lines of the labeled statement


def writes_in(lines):
    """All destination-write ops: (rel_line, kind, dest_expr, full_line)."""
    out = []
    for i, l in enumerate(lines):
        m = COPY.search(l)
        if m:
            after = l[m.end():]
            dm = re.match(r"\s*([^,]+?)\s*,", after)
            out.append((i, "copy_sink", (dm.group(1).strip() if dm else "?"), l.strip()))
            continue
        m = IDXW.search(l)
        if m:
            out.append((i, "index_write", m.group(1).strip(), l.strip())); continue
        m = DEREFW.search(l)
        if m and "==" not in l:
            out.append((i, "pointer_deref", m.group(1).strip(), l.strip()))
    return out


def locate_label(lines, labeled):
    """Return the rel_line(s) of the labeled statement text within func_body (text match,
    not absolute line arithmetic)."""
    hits = []
    for pair in (labeled or []):
        txt = (pair[1] if isinstance(pair, (list, tuple)) and len(pair) > 1 else str(pair)).strip()
        if not txt:
            continue
        for i, l in enumerate(lines):
            if txt and txt in l:
                hits.append(i)
    return sorted(set(hits))


def map_write(func_body, labeled):
    """RULE 1. Deterministic unique mapping. Returns (status, write_or_None)."""
    lines = func_body.splitlines()
    ws = writes_in(lines)
    if not ws:
        return "no_write_found", None
    labs = locate_label(lines, labeled)
    if not labs:
        # no anchor -> only accept if the function has exactly ONE write (unambiguous)
        return ("mapped", ws[0]) if len(ws) == 1 else ("ambiguous", None)
    # candidate writes within +-WINDOW of any labeled line; a labeled line that IS a write counts
    cand = [w for w in ws if any(abs(w[0] - L) <= WINDOW for L in labs)]
    uniq = {(w[1], w[2], w[0]) for w in cand}
    if len(uniq) == 1:
        return "mapped", cand[0]
    if len(cand) == 0:
        return "no_write_found", None
    return "ambiguous", None


_TYPE = re.compile(r"\b(char|wchar_t|unsigned char|signed char|int|short|long|size_t|"
                   r"uint\d+_t|int\d+_t|float|double|void)\b")


def dest_shape(func_body, dest_expr):
    """RULE 2 helper: structural shape of the destination, from source decls only."""
    d = dest_expr.strip()
    base = re.match(r"&?\s*\(?\s*([A-Za-z_]\w*)", d)
    base = base.group(1) if base else d
    if "->" in d or re.search(r"\b\w+\.\w+", d):
        return "struct_field"
    if re.search(rf"\b(?:char|int|short|long|wchar_t|uint\d+_t|int\d+_t|unsigned)\s+{re.escape(base)}\s*\[", func_body):
        return "local_array"
    if re.search(rf"\b{re.escape(base)}\s*=\s*\(?[^;]*\b(?:malloc|calloc|realloc|alloca)\b", func_body):
        return "heap_alloc"
    if re.search(rf"\([^)]*\b\w[\w ]*\*\s*{re.escape(base)}\b[^)]*\)\s*\{{", func_body) or \
       re.search(rf"\([^)]*\b{re.escape(base)}\b[^)]*\)\s*\{{", func_body.split("{")[0] + "{"):
        return "parameter"
    return "unknown"


def length_shape(write_line, kind):
    if kind != "copy_sink":
        return "index" if kind == "index_write" else "deref"
    m = re.search(r"\([^,]*,[^,]*,([^;]*)\)\s*;?", write_line)
    if not m:
        return "implicit_or_2arg"
    s = m.group(1)
    s = re.sub(r"\b(?:strlen|wcslen)\b", "LEN", s)
    s = re.sub(r"\bsizeof\b", "SZ", s)
    s = re.sub(r"\d+", "N", s)
    s = re.sub(r"[A-Za-z_]\w*", "V", s)
    return re.sub(r"\s+", "", s)


def family_id(func_body, write):
    """RULE 2. Deterministic family from structure only."""
    _, kind, dest_expr, line = write
    sig = f"{kind}|{dest_shape(func_body, dest_expr)}|{length_shape(line, kind)}"
    return sig, "fam_" + hashlib.sha256(sig.encode()).hexdigest()[:12]


def main():
    subset_path, commit = sys.argv[1], sys.argv[2]
    raw = open(subset_path, "rb").read()
    d = json.loads(raw)
    recs = []
    for cwe, lst in d.items():
        for r in lst:
            r = dict(r); r["cwe"] = cwe; recs.append(r)

    excl = Counter()
    sites, seen = [], set()
    for r in recs:
        if r["cwe"] in AMBIGUOUS_CWE:
            excl["ambiguous_cwe_119"] += 1; continue
        if r["cwe"] not in INCLUDE_CWE:
            excl["other_cwe_not_write"] += 1; continue
        if r["project"].lower() in MAGMA_PROJECTS:
            excl["magma_overlap_project"] += 1; continue
        key = (r["project"], r["commit_id"], r["filepath"], r["func_name"])
        if key in seen:
            excl["duplicate_site"] += 1; continue
        seen.add(key)
        fb = r.get("func_body") or ""
        status, w = map_write(fb, r.get("line_statements") or r.get("statements"))
        rec = {"site_id": hashlib.sha256("|".join(key).encode()).hexdigest()[:16],
               "project": r["project"], "commit_id": r["commit_id"], "filepath": r["filepath"],
               "func_name": r["func_name"], "cve": r["cve"], "cwe": r["cwe"],
               "is_vulnerable": r["is_vulnerable"], "func_body_sha256": hashlib.sha256(fb.encode()).hexdigest(),
               "labeled_statements": r.get("statements"), "mapping_status": status}
        if status == "mapped":
            rec["write_kind"] = w[1]; rec["write_dest"] = w[2]; rec["write_line"] = w[3]
            sig, fid = family_id(fb, w)
            rec["family_signature"] = sig; rec["family_id"] = fid
        sites.append(rec)

    mapped = [s for s in sites if s["mapping_status"] == "mapped"]
    mapped_vuln = [s for s in mapped if s["is_vulnerable"]]
    fams_vuln = {s["family_id"] for s in mapped_vuln}
    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False,
        "source": "SecVulEval basimbd/SecVulEval random_subset.json",
        "pinned_commit": commit, "random_subset_sha256": hashlib.sha256(raw).hexdigest(),
        "full_dataset_status": "HuggingFace arag0rn/SecVulEval is proxy-BLOCKED (403) in this "
                               "environment; only random_subset.json is reachable. This freeze "
                               "is the reachable population; expansion needs an unblocked fetch.",
        "rule_1_write_site_mapping": f"deterministic text-only mapping of labeled statement -> a "
                                     f"UNIQUE destination write within +-{WINDOW} source lines "
                                     f"(or the sole write if no anchor); mapped/ambiguous/"
                                     f"no_write_found; only mapped sites score.",
        "rule_2_family_assignment": "deterministic family_id = hash(write_kind | dest_shape | "
                                    "length_shape) from source structure only; frozen now, never "
                                    "recomputed after scanner outputs are seen.",
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_total": len(mapped),
            "mapped_vulnerable": len(mapped_vuln),
            "mapped_non_vulnerable": len(mapped) - len(mapped_vuln),
            "vulnerable_families": len(fams_vuln),
            "family_by_vuln_count": dict(Counter(s["family_id"] for s in mapped_vuln)),
            "by_cwe_mapped": dict(Counter(s["cwe"] for s in mapped)),
        },
        "twelve_vuln_family_gate": {"gate": 12, "vulnerable_families": len(fams_vuln),
                                    "meets_gate": len(fams_vuln) >= 12},
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "secvuleval",
                        "FROZEN_heldout.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("SITES after filters:", len(sites), " exclusions:", dict(excl))
    print("MAPPING:", dict(Counter(s["mapping_status"] for s in sites)))
    print(f"MAPPED total {len(mapped)}  (vulnerable {len(mapped_vuln)} / non-vuln {len(mapped)-len(mapped_vuln)})")
    print(f"VULNERABLE FAMILIES: {len(fams_vuln)}  (12-gate: {'MEETS' if len(fams_vuln)>=12 else 'BELOW'})")
    print(f"vulnerable family sig sample:", [s['family_signature'] for s in mapped_vuln[:6]])
    print(f"frozen -> {outp}")


if __name__ == "__main__":
    main()
