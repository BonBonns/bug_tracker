#!/usr/bin/env python3
"""Build the frozen scanner corpus with full attribution and cross-producer
de-duplication.

This is the corpus-building machinery for the semantic-bucket experiment. It
is committed BEFORE it is run to produce the frozen outputs, so the frozen
corpus can never be the product of an uncommitted builder (see FREEZE.md,
"build sequencing").

Run the three reason-emitting producers (RUNTIME_CAPACITY, CURSOR,
INTERPROCEDURAL) over the real CVE fact-file corpus and emit, from that same
frozen run:

  1. all_records.jsonl        -- every analysis record, one per (producer,
                                 recognized operation). The raw producer-boundary
                                 view; accounting equality is asserted here.
  2. distinct_operations.jsonl-- de-duplicated to one canonical record per
                                 physical operation (cross-producer fingerprint).
                                 THIS is the experimental-case universe: the same
                                 write recognized by two producers, or reached via
                                 two cached fact files, is one case, not several.
  3. llm_eligible.jsonl       -- the distinct operations whose canonical record
                                 is llm_eligible. What A/B/C may draw from.

  4. manifest.json            -- full attribution: scanner commit, schema version
                                 + hash, builder self-hash, per-producer file
                                 hashes, per-input fact hashes, source-repo
                                 revisions, tool versions, pipeline reference.
  5. audit.json / audit.md    -- distributions by producer / status / reason /
                                 bucket / route / llm-eligibility / source file /
                                 vuln-vs-patched, plus de-duplication statistics.

INVARIANTS asserted (build aborts on violation -- a frozen corpus must not
silently drop or misattribute a recognized operation):
  * accounting equality per (input file, producer):
      recognized = deterministic_complete + open_candidate + abstained + rerouted
  * every abstention record carries the full required field set.
  * every emitted reason belongs to frozen schema v1.

De-duplication is EVIDENCE-MONOTONE, not producer-name-privileged: for one
physical operation seen by multiple producers, the canonical record is the one
that established the most evidence (got furthest along the prerequisite chain:
identity -> capacity -> bound). Ties break deterministically. All alternative
producer verdicts are retained under `producer_verdicts`, and genuine
disagreements are flagged `dedup_conflict`, so nothing is hidden by the merge.

SCANNER STATE IS NOT GROUND TRUTH. Every record here is what the scanner
emitted, not the verified answer. `uncertainty_bucket` is the scanner-emitted
bucket; establishing the verified bucket, the verified program outcome, and the
evidence-relative answer is a separate downstream layer (see FREEZE.md).
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = subprocess.check_output(
    ["git", "-C", HERE, "rev-parse", "--show-toplevel"]).decode().strip()
PKG = os.path.join(REPO, "tchecker-research-complete", "portable-engine-full-review-package")
TOOLS = os.path.join(PKG, "tools")

REASON_PRODUCERS = (
    "oob_runtime_capacity_verdict",
    "oob_cursor_write_verdict",
    "oob_interprocedural_verdict",
)

# The real CVE corpus. Each label -> the cached fact-file path PLUS the source
# provenance needed to regenerate that fact file deterministically. Source
# revisions are recorded in moz-scan-paired-cve-validation-round1.md; a scan is
# `scan_pkg.sh <checkout> <out>` with joern-c2cpg 4.0.608 (schema
# portable-program-facts/0.3). vuln = the anchor commit's parent (^), patched =
# the anchor commit itself.
CORPUS = {
    "cve-2019-17006/vuln":    dict(path="/tmp/cve-2019-17006/vuln/scan/work/cpp.json",
        cve="CVE-2019-17006", bug="NSS bug 1539788", repo="github.com/mozilla/nss",
        anchor="0bf553163", side="vuln", file="lib/freebl/rsapkcs.c"),
    "cve-2019-17006/patched": dict(path="/tmp/cve-2019-17006/patched/scan/work/cpp.json",
        cve="CVE-2019-17006", bug="NSS bug 1539788", repo="github.com/mozilla/nss",
        anchor="0bf553163", side="patched", file="lib/freebl/rsapkcs.c"),
    "mjpg-cve-huff/vuln":     dict(path="/tmp/mjpg-cve-huff/vuln/scan/work/cpp.json",
        cve="Debian #768369", bug="mozjpeg Huffman local buffer overrun", repo="github.com/mozilla/mozjpeg",
        anchor="a06aeb25", side="vuln", file="jchuff.c"),
    "mjpg-cve-huff/patched":  dict(path="/tmp/mjpg-cve-huff/patched/scan/work/cpp.json",
        cve="Debian #768369", bug="mozjpeg Huffman local buffer overrun", repo="github.com/mozilla/mozjpeg",
        anchor="a06aeb25", side="patched", file="jchuff.c"),
    "cve-2019-11745/vuln":    dict(path="/tmp/cve-2019-11745/vuln/scan/work/cpp.json",
        cve="CVE-2019-11745", bug="NSS bug 1586176", repo="github.com/mozilla/nss",
        anchor="0271ef66e", side="vuln", file="lib/softoken/pkcs11c.c"),
    "cve-2019-11745/patched": dict(path="/tmp/cve-2019-11745/patched/scan/work/cpp.json",
        cve="CVE-2019-11745", bug="NSS bug 1586176", repo="github.com/mozilla/nss",
        anchor="0271ef66e", side="patched", file="lib/softoken/pkcs11c.c"),
    "cve-2016-1950/vuln":     dict(path="/tmp/cve-2016-1950/vuln/scan/work/cpp.json",
        cve="CVE-2016-1950", bug="NSS bug 1245528", repo="github.com/mozilla/nss",
        anchor="994c45e80", side="vuln", file="lib/util/secasn1d.c"),
    "cve-2016-1950/patched":  dict(path="/tmp/cve-2016-1950/patched/scan/work/cpp.json",
        cve="CVE-2016-1950", bug="NSS bug 1245528", repo="github.com/mozilla/nss",
        anchor="994c45e80", side="patched", file="lib/util/secasn1d.c"),
    "cve-2021-43527/vuln":    dict(path="/tmp/cve-2021-43527/vuln/scan/work/cpp.json",
        cve="CVE-2021-43527", bug="NSS bug 1737470", repo="github.com/mozilla/nss",
        anchor="73a449016", side="vuln", file="lib/cryptohi/secvfy.c"),
    "cve-2021-43527/patched": dict(path="/tmp/cve-2021-43527/patched/scan/work/cpp.json",
        cve="CVE-2021-43527", bug="NSS bug 1737470", repo="github.com/mozilla/nss",
        anchor="73a449016", side="patched", file="lib/cryptohi/secvfy.c"),
    "cve-2019-11759/vuln":    dict(path="/tmp/cve-2019-11759/vuln/scan/work/cpp.json",
        cve="CVE-2019-11759", bug="NSS bug 1577953", repo="github.com/mozilla/nss",
        anchor="deb6103d0", side="vuln", file="lib/softoken/pkcs11c.c"),
    "cve-2019-11759/patched": dict(path="/tmp/cve-2019-11759/patched/scan/work/cpp.json",
        cve="CVE-2019-11759", bug="NSS bug 1577953", repo="github.com/mozilla/nss",
        anchor="deb6103d0", side="patched", file="lib/softoken/pkcs11c.c"),
}

# Tool versions the fact files were produced with (from fact-file metadata +
# the scan pipeline). repo_rev_informational is UNVERSIONED in the artifacts
# themselves -- an honest provenance gap noted in the manifest.
TOOLCHAIN = {
    "frontend": "joern-c2cpg",
    "frontend_version": "4.0.608",
    "facts_schema": "portable-program-facts/0.3",
    "scan_pipeline": "tchecker-research-complete/gates/scan_pkg.sh",
    "note": ("Fact files carry frontend version + schema but NOT the source "
             "repo revision (report.json repo_rev_informational == "
             "'UNVERSIONED'); source revisions come from "
             "moz-scan-paired-cve-validation-round1.md and are recorded per "
             "input below. To regenerate an input: git clone the repo, check "
             "out the anchor commit (patched) or its parent (vuln), then run "
             "scan_pkg.sh over the checkout with joern-c2cpg 4.0.608."),
}

REQUIRED_ABSTENTION_FIELDS = (
    "operation_id", "analysis_status", "all_reason_codes", "primary_reason_code",
    "uncertainty_bucket", "recommended_route", "llm_eligible",
)

# Evidence rank: how far along the prerequisite chain a producer got for this
# operation. Higher = more evidence established. Used ONLY to pick the canonical
# record when producers disagree on one physical operation; producer name is
# never itself privileged.
EVIDENCE_RANK = {
    "deterministic_complete": 3,   # identity + capacity established, bound proven
    "open_candidate": 3,           # identity + capacity established, bound open
    "rerouted": 2,                 # established, but a different (lifetime) property
    "abstained": 1,                # a prerequisite is missing
}


def _load(modname):
    if TOOLS not in sys.path:
        sys.path.insert(0, TOOLS)
    s = importlib.util.spec_from_file_location(modname, os.path.join(TOOLS, modname + ".py"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_rev():
    return subprocess.check_output(["git", "-C", HERE, "rev-parse", "HEAD"]).decode().strip()


def _git_dirty(relpaths):
    """True if any of the given repo-relative paths has uncommitted changes."""
    out = subprocess.check_output(
        ["git", "-C", REPO, "status", "--porcelain"] + relpaths).decode()
    return bool(out.strip())


def _fingerprint(rec):
    """Producer-INDEPENDENT stable fingerprint for one physical operation.
    Two producers seeing the same write, or the same write reached via two
    cached fact files of the same revision, map to the same fingerprint."""
    key = "|".join(str(x) for x in (
        rec.get("_source_label"), rec.get("file"), rec.get("function"),
        rec.get("line"), rec.get("dest")))
    return "op_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _canonical(group):
    """Pick the canonical record for a set of records sharing a fingerprint.
    Evidence-monotone: prefer the most evidence established; deterministic tie
    break by producer order then operation_id. Retains all producer verdicts and
    flags genuine disagreement."""
    ordered = sorted(
        group,
        key=lambda r: (-EVIDENCE_RANK.get(r["analysis_status"], 0),
                       REASON_PRODUCERS.index(r["_producer"]),
                       str(r.get("operation_id"))))
    canon = dict(ordered[0])
    verdicts = [{"producer": r["_producer"], "analysis_status": r["analysis_status"],
                 "primary_reason_code": r.get("primary_reason_code"),
                 "uncertainty_bucket": r.get("uncertainty_bucket")} for r in ordered]
    canon["producer_verdicts"] = verdicts
    canon["seen_by_producers"] = [r["_producer"] for r in ordered]
    distinct = {(v["analysis_status"], v["primary_reason_code"]) for v in verdicts}
    canon["dedup_conflict"] = len(distinct) > 1
    return canon


def _accounting(recs):
    sc = Counter(r["analysis_status"] for r in recs)
    total = sc["deterministic_complete"] + sc["open_candidate"] + sc["abstained"] + sc["rerouted"]
    return total == len(recs), sc


def main():
    # Guard: the machinery that produces the frozen corpus must itself be
    # committed, so the outputs are attributable to a specific builder + scanner.
    machinery = [
        "semantic-bucket-pilot/frozen-corpus/build_frozen_corpus.py",
        "tchecker-research-complete/portable-engine-full-review-package/tools/oob_runtime_capacity_verdict.py",
        "tchecker-research-complete/portable-engine-full-review-package/tools/oob_cursor_write_verdict.py",
        "tchecker-research-complete/portable-engine-full-review-package/tools/oob_interprocedural_verdict.py",
        "tchecker-research-complete/portable-engine-full-review-package/tools/analysis_record.py",
    ]
    strict = "--allow-dirty" not in sys.argv
    if strict and _git_dirty(machinery):
        raise SystemExit(
            "REFUSING TO BUILD: builder/producer/schema files have uncommitted "
            "changes. Commit the machinery first so the frozen corpus is "
            "attributable to a committed builder + scanner (see FREEZE.md build "
            "sequencing). Re-run with --allow-dirty only for a dry run.")

    mods = {name: _load(name) for name in REASON_PRODUCERS}

    all_records = []
    manifest_inputs = []
    missing = []
    for label, meta in CORPUS.items():
        path = meta["path"]
        if not os.path.exists(path):
            missing.append(label)
            continue
        entry = {"label": label, "path": path, "sha256": _sha256_file(path),
                 "cve": meta["cve"], "bug": meta["bug"], "repo": meta["repo"],
                 "anchor_commit": meta["anchor"], "side": meta["side"],
                 "revision": (meta["anchor"] + "^" if meta["side"] == "vuln"
                              else meta["anchor"]),
                 "source_file": meta["file"], "producers": {}}
        for name, mod in mods.items():
            recs = mod.analyze_operations(path)
            ok, sc = _accounting(recs)
            if not ok:
                raise SystemExit(f"ACCOUNTING VIOLATION {label}/{name}: "
                                 f"{len(recs)} records vs det+open+abstained+rerouted={dict(sc)}")
            for r in recs:
                if r["analysis_status"] == "abstained":
                    miss = [f for f in REQUIRED_ABSTENTION_FIELDS if f not in r]
                    if miss:
                        raise SystemExit(f"ABSTENTION MISSING FIELDS {label}/{name} "
                                         f"{r.get('function')}:{r.get('line')}: {miss}")
                r["_source_label"] = label
                r["_producer"] = name
                r["_side"] = meta["side"]
                r["_cve"] = meta["cve"]
                r["op_fingerprint"] = _fingerprint(r)
            all_records.extend(recs)
            entry["producers"][name] = dict(sc)
        manifest_inputs.append(entry)

    # cross-producer de-duplication to distinct physical operations
    groups = defaultdict(list)
    for r in all_records:
        groups[r["op_fingerprint"]].append(r)
    distinct = [_canonical(g) for g in groups.values()]
    distinct.sort(key=lambda r: (r.get("_source_label"), str(r.get("function")),
                                 r.get("line") or 0, str(r.get("dest"))))
    llm_eligible = [r for r in distinct if r.get("llm_eligible") is True]

    def _write(fn, rows):
        with open(os.path.join(HERE, fn), "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    _write("all_records.jsonl", all_records)
    _write("distinct_operations.jsonl", distinct)
    _write("llm_eligible.jsonl", llm_eligible)

    # ---- attribution manifest ----
    def _hash_repo_file(rel):
        return _sha256_file(os.path.join(REPO, rel))
    manifest = {
        "scanner_commit": _git_rev(),
        "reason_emitting_producers": list(REASON_PRODUCERS),
        "schema": {
            "facts_schema": TOOLCHAIN["facts_schema"],
            "analysis_record_version": "1",
            "analysis_record_sha256": _hash_repo_file(
                "tchecker-research-complete/portable-engine-full-review-package/tools/analysis_record.py"),
        },
        "builder_sha256": _sha256_file(os.path.abspath(__file__)),
        "producer_sha256": {name: _hash_repo_file(
            f"tchecker-research-complete/portable-engine-full-review-package/tools/{name}.py")
            for name in REASON_PRODUCERS},
        "toolchain": TOOLCHAIN,
        "coverage_note": ("Only the three reason-emitting producers carry the "
                          "full accounting + reason layer and contribute "
                          "analysis records; the other producers emit warning "
                          "candidates but no accounting records and are out of "
                          "this corpus by design, not dropped."),
        "inputs": manifest_inputs,
        "missing_inputs": missing,
        "counts": {
            "all_records": len(all_records),
            "distinct_operations": len(distinct),
            "llm_eligible": len(llm_eligible),
            "cross_producer_merged": len(all_records) - len(distinct),
            "dedup_conflicts": sum(1 for r in distinct if r.get("dedup_conflict")),
        },
    }
    with open(os.path.join(HERE, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)

    # ---- audit distributions (over DISTINCT operations = experimental cases) ----
    def _dist(key):
        return dict(Counter(str(r.get(key)) for r in distinct))
    audit = {
        "universe": "distinct_operations (one canonical record per physical op)",
        "n_distinct_operations": len(distinct),
        "n_raw_records": len(all_records),
        "by_producer_canonical": dict(Counter(r["_producer"] for r in distinct)),
        "by_status": _dist("analysis_status"),
        "by_primary_reason": dict(Counter(
            str(r.get("primary_reason_code")) for r in distinct
            if r["analysis_status"] != "deterministic_complete")),
        "by_bucket": _dist("uncertainty_bucket"),
        "by_route": _dist("recommended_route"),
        "by_llm_eligible": dict(Counter(str(r.get("llm_eligible")) for r in distinct)),
        "by_source_label": _dist("_source_label"),
        "by_cve": _dist("_cve"),
        "by_side_vuln_patched": _dist("_side"),
        "dedup": {
            "raw_records": len(all_records),
            "distinct_operations": len(distinct),
            "merged_away": len(all_records) - len(distinct),
            "conflicts": sum(1 for r in distinct if r.get("dedup_conflict")),
            "conflict_examples": [
                {"op": r["op_fingerprint"], "function": r.get("function"),
                 "line": r.get("line"), "source": r.get("_source_label"),
                 "verdicts": r["producer_verdicts"]}
                for r in distinct if r.get("dedup_conflict")][:10],
        },
    }
    with open(os.path.join(HERE, "audit.json"), "w") as fh:
        json.dump(audit, fh, indent=2, sort_keys=True)

    _write_audit_md(audit, manifest)

    print(f"scanner_commit       {manifest['scanner_commit']}")
    print(f"inputs present       {len(manifest_inputs)}/{len(CORPUS)}"
          + (f"  MISSING {missing}" if missing else ""))
    print(f"raw records          {len(all_records)}")
    print(f"distinct operations  {len(distinct)}  (merged away {len(all_records)-len(distinct)}, "
          f"conflicts {audit['dedup']['conflicts']})")
    print(f"llm_eligible         {len(llm_eligible)}")
    print(f"by_status            {audit['by_status']}")
    print(f"by_bucket            {audit['by_bucket']}")
    print(f"by_route             {audit['by_route']}")


def _write_audit_md(audit, manifest):
    def tbl(title, d):
        rows = "\n".join(f"| {k} | {v} |" for k, v in sorted(
            d.items(), key=lambda kv: (-kv[1], kv[0])))
        return f"\n### {title}\n\n| key | count |\n|-----|-------|\n{rows}\n"
    lines = [
        "# Frozen corpus audit\n",
        f"Scanner commit `{manifest['scanner_commit']}`. Universe: "
        f"**{audit['n_distinct_operations']} distinct operations** "
        f"(de-duplicated from {audit['n_raw_records']} raw producer records).\n",
        "> Every count below is a **scanner-emitted** state, not verified "
        "ground truth. The verified bucket and program outcome are established "
        "by a separate downstream layer.\n",
        tbl("By analysis status", audit["by_status"]),
        tbl("By primary reason (non-deterministic)", audit["by_primary_reason"]),
        tbl("By uncertainty bucket", audit["by_bucket"]),
        tbl("By recommended route", audit["by_route"]),
        tbl("By LLM-eligibility", audit["by_llm_eligible"]),
        tbl("By canonical producer", audit["by_producer_canonical"]),
        tbl("By CVE", audit["by_cve"]),
        tbl("By revision side", audit["by_side_vuln_patched"]),
        tbl("By source label", audit["by_source_label"]),
        f"\n### De-duplication\n\n"
        f"- raw records: {audit['dedup']['raw_records']}\n"
        f"- distinct operations: {audit['dedup']['distinct_operations']}\n"
        f"- merged away (same op seen by >1 producer): {audit['dedup']['merged_away']}\n"
        f"- genuine disagreements (flagged `dedup_conflict`): {audit['dedup']['conflicts']}\n",
    ]
    if audit["dedup"]["conflict_examples"]:
        lines.append("\nConflicts (canonical = highest evidence; alternatives retained):\n")
        for c in audit["dedup"]["conflict_examples"]:
            vs = "; ".join(f"{v['producer'].split('_')[1]}:{v['analysis_status']}/"
                           f"{v['primary_reason_code']}" for v in c["verdicts"])
            lines.append(f"- `{c['source']}` {c['function']}:{c['line']} — {vs}")
    with open(os.path.join(HERE, "audit.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
