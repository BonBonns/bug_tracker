#!/usr/bin/env python3
"""Combined-reporting regression (task #43, item 4): a raw CANDIDATE record from any of the
three OOB producers (oob_write_candidates / oob_read_candidates / oob_compare_candidates) must
NEVER be counted as a reportable finding merely because provenance.enrich_record() resolved its
source file. This is the same one-way rule #35 established for R04/R05/LOCK_BALANCE/
PROTECTED_FIELD (the node-libcurl regression in check_provenance.py), checked here specifically
for the three OOB properties, which #35's PROPERTY_CANDIDATE_RULES marks scanner_candidate=True
unconditionally (every record their own emit_candidates() ever appends IS a real candidate by
construction -- see provenance.py's own PROPERTY_CANDIDATE_RULES comment). That unconditional
True makes provenance.resolved the ONLY other gate standing between a raw scanner CANDIDATE and
reportable=True -- so this must be verified explicitly, not assumed, for all three OOB keys.

Self-contained: builds a minimal real on-disk package + methods.tsv fixture (no c2cpg needed --
this only exercises the reportability formula and the function_id join, not any scanner's own
verdict logic).
"""
import base64, json, os, pathlib, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import provenance

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)

def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

with tempfile.TemporaryDirectory() as td:
    pkg_dir = os.path.join(td, "pkg")
    cpp_raw = os.path.join(td, "cpp_raw")
    os.makedirs(pkg_dir)
    os.makedirs(cpp_raw)

    site_relpath = "src/site.cpp"
    os.makedirs(os.path.join(pkg_dir, "src"))
    with open(os.path.join(pkg_dir, site_relpath), "w") as f:
        f.write("void f() { memcpy(out, spec->expstr, 6); }\n")  # the unsafe (6>5) sibling site

    # methods.tsv: id, ..., file(base64, col index 4), ... (>=10 cols; only col 0 and 4 matter
    # to load_method_file_map, per its own parsing).
    function_id = 555
    row = [str(function_id), "x", "x", "x", b64(site_relpath), "x", "x", "x", "x", "x"]
    with open(os.path.join(cpp_raw, "methods.tsv"), "w") as f:
        f.write("\t".join(row) + "\n")

    manifest = provenance.build_source_manifest(pkg_dir, b"fake-tarball-bytes", "synthetic-pkg", "1.0.0")

    for candidates_key in ("oob_write_candidates", "oob_index_write_candidates",
                           "oob_read_candidates", "oob_compare_candidates"):
        record = {candidates_key: [{
            "verdict": "CANDIDATE",
            "class": candidates_key.split("_candidates")[0].upper(),
            "function": "f", "line": 1, "call": "memcpy",
            "extent_value_id": -1, "src_capacity_bytes": 5,
            "call_id": 30064827809, "function_id": function_id,
            "site_id": f"f:1:memcpy",
        }]}
        provenance.enrich_record(record, cpp_raw, manifest, pkg_dir)
        c = record[candidates_key][0]

        ck(f"{candidates_key}: scanner_candidate=True (this producer's own verdict vocabulary is unconditionally real)",
           c["scanner_candidate"] is True)
        ck(f"{candidates_key}: provenance.resolved=True (real file, real content hash)",
           c["provenance"]["resolved"] is True)
        ck(f"{candidates_key}: applicability_status defaults to NOT_YET_DETERMINED, never fabricated APPLICABLE",
           c["applicability_status"] == "NOT_YET_DETERMINED")
        ck(f"{candidates_key}: *** reportable=False despite scanner_candidate=True AND provenance.resolved=True *** "
           f"-- a raw CANDIDATE must never be counted as a reportable finding by default",
           c["reportable"] is False)

    # Negative control: reportable only flips True once applicability is affirmatively established
    # AND it is not already adjudicated a false positive -- i.e. the gate is not simply unreachable,
    # it responds correctly to real affirmative evidence when that evidence actually exists.
    record = {"oob_read_candidates": [{
        "verdict": "CANDIDATE", "class": "OOB_READ", "function": "f", "line": 1, "call": "memcpy",
        "extent_value_id": -1, "src_capacity_bytes": 5, "call_id": 30064827809,
        "function_id": function_id, "site_id": "f:1:memcpy",
        "applicability_status": "APPLICABLE",
    }]}
    provenance.enrich_record(record, cpp_raw, manifest, pkg_dir)
    c = record["oob_read_candidates"][0]
    ck("control: with an existing, real APPLICABLE status (never fabricated by this module) reportable=True",
       c["reportable"] is True)

print(f"OOB_REPORTABLE_GATE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
