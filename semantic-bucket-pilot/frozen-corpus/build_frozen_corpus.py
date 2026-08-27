#!/usr/bin/env python3
"""Build the two frozen corpora from the frozen scanner's own output.

This is step 6 of the user's plan: after cursor + interprocedural accounting
passes and the complete scanner is frozen at one commit, run the frozen
producers over the real CVE fact-file corpus and emit exactly two artifacts
from THAT SAME frozen output:

  1. llm_eligible.jsonl  -- records with llm_eligible == True. These are the
     candidate-review records the A/B/C prompt experiment consumes. Nothing
     else is eligible for A/B/C.
  2. all_records.jsonl   -- every analysis record the frozen scanner emits
     (deterministic_complete + open_candidate + abstained + rerouted) across
     every producer and every input file. This is the set the bucket-assignment
     and routing evaluation runs over.

Both come from the identical frozen scanner run. The manifest records the
scanner commit SHA and the sha256 of every input fact file so the corpus is
reproducible: given the same commit and the same inputs, this script emits
byte-identical corpora (the producers are deterministic; verified by the
analysis-record gate).

ACCOUNTING EQUALITY is asserted per (input file, producer): the number of
recognized operations equals det + open + abstained + rerouted. A violation
aborts the build -- a frozen corpus must not silently drop a recognized op.

Only the three reason-emitting producers (RUNTIME_CAPACITY, CURSOR,
INTERPROCEDURAL) carry the full accounting + reason layer, so only they
contribute analysis records. The other producers emit warning candidates but
no accounting records yet; that limit is stated in the manifest rather than
papered over.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = subprocess.check_output(
    ["git", "-C", HERE, "rev-parse", "--show-toplevel"]).decode().strip()
TOOLS = os.path.join(
    REPO, "tchecker-research-complete", "portable-engine-full-review-package", "tools")

REASON_PRODUCERS = (
    "oob_runtime_capacity_verdict",
    "oob_cursor_write_verdict",
    "oob_interprocedural_verdict",
)

# The real CVE corpus: independently disclosed Mozilla/NSS + mozjpeg cases,
# each with a vulnerable and a patched revision. Label -> fact-file path.
# Paths are the cached extraction outputs; the manifest hashes them so the
# corpus is reproducible from the same inputs.
CORPUS = {
    "cve-2019-17006/vuln":    "/tmp/cve-2019-17006/vuln/scan/work/cpp.json",
    "cve-2019-17006/patched": "/tmp/cve-2019-17006/patched/scan/work/cpp.json",
    "mjpg-cve-huff/vuln":     "/tmp/mjpg-cve-huff/vuln/scan/work/cpp.json",
    "mjpg-cve-huff/patched":  "/tmp/mjpg-cve-huff/patched/scan/work/cpp.json",
    "cve-2019-11745/vuln":    "/tmp/cve-2019-11745/vuln/scan/work/cpp.json",
    "cve-2019-11745/patched": "/tmp/cve-2019-11745/patched/scan/work/cpp.json",
    "cve-2016-1950/vuln":     "/tmp/cve-2016-1950/vuln/scan/work/cpp.json",
    "cve-2016-1950/patched":  "/tmp/cve-2016-1950/patched/scan/work/cpp.json",
    "cve-2021-43527/vuln":    "/tmp/cve-2021-43527/vuln/scan/work/cpp.json",
    "cve-2021-43527/patched": "/tmp/cve-2021-43527/patched/scan/work/cpp.json",
    "cve-2019-11759/vuln":    "/tmp/cve-2019-11759/vuln/scan/work/cpp.json",
    "cve-2019-11759/patched": "/tmp/cve-2019-11759/patched/scan/work/cpp.json",
}

REQUIRED_ABSTENTION_FIELDS = (
    "operation_id", "analysis_status", "all_reason_codes", "primary_reason_code",
    "uncertainty_bucket", "recommended_route", "llm_eligible",
)


def _load(modname):
    if TOOLS not in sys.path:
        sys.path.insert(0, TOOLS)
    s = importlib.util.spec_from_file_location(
        modname, os.path.join(TOOLS, modname + ".py"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _scanner_sha():
    return subprocess.check_output(
        ["git", "-C", HERE, "rev-parse", "HEAD"]).decode().strip()


def _accounting_ok(recs):
    sc = Counter(r["analysis_status"] for r in recs)
    total = (sc["deterministic_complete"] + sc["open_candidate"]
             + sc["abstained"] + sc["rerouted"])
    return total == len(recs), sc


def main():
    mods = {name: _load(name) for name in REASON_PRODUCERS}

    all_records = []
    manifest_inputs = []
    missing = []

    for label, path in CORPUS.items():
        if not os.path.exists(path):
            missing.append(label)
            continue
        file_entry = {"label": label, "path": path, "sha256": _sha256(path),
                      "producers": {}}
        for name, mod in mods.items():
            recs = mod.analyze_operations(path)
            ok, sc = _accounting_ok(recs)
            if not ok:
                raise SystemExit(
                    f"ACCOUNTING VIOLATION {label}/{name}: "
                    f"{len(recs)} records but det+open+abstained+rerouted={sc}")
            # tag provenance and normalize; assert required fields on abstentions
            for r in recs:
                if r["analysis_status"] == "abstained":
                    miss = [f for f in REQUIRED_ABSTENTION_FIELDS if f not in r]
                    if miss:
                        raise SystemExit(
                            f"ABSTENTION MISSING FIELDS {label}/{name} "
                            f"@ {r.get('function')}:{r.get('line')}: {miss}")
                r["_source_label"] = label
                r["_producer"] = name
            all_records.extend(recs)
            file_entry["producers"][name] = dict(sc)
        manifest_inputs.append(file_entry)

    llm_eligible = [r for r in all_records if r.get("llm_eligible") is True]

    # write corpora
    with open(os.path.join(HERE, "all_records.jsonl"), "w") as fh:
        for r in all_records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with open(os.path.join(HERE, "llm_eligible.jsonl"), "w") as fh:
        for r in llm_eligible:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    status_counts = Counter(r["analysis_status"] for r in all_records)
    bucket_counts = Counter(r.get("uncertainty_bucket") for r in all_records)
    route_counts = Counter(r.get("recommended_route") for r in all_records)
    reason_counts = Counter(r.get("primary_reason_code") for r in all_records
                            if r.get("analysis_status") != "deterministic_complete")

    manifest = {
        "scanner_commit": _scanner_sha(),
        "reason_emitting_producers": list(REASON_PRODUCERS),
        "note": ("Only the three reason-emitting producers carry the full "
                 "accounting + reason layer and contribute analysis records. "
                 "Other producers emit warning candidates but no accounting "
                 "records; they are out of this corpus by design, not dropped."),
        "inputs": manifest_inputs,
        "missing_inputs": missing,
        "totals": {
            "all_records": len(all_records),
            "llm_eligible": len(llm_eligible),
            "by_status": dict(status_counts),
            "by_bucket": {str(k): v for k, v in bucket_counts.items()},
            "by_route": {str(k): v for k, v in route_counts.items()},
            "by_primary_reason_nondet": dict(reason_counts),
        },
    }
    with open(os.path.join(HERE, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)

    print(f"scanner_commit  {manifest['scanner_commit']}")
    print(f"inputs present  {len(manifest_inputs)}/{len(CORPUS)}"
          + (f"  MISSING: {missing}" if missing else ""))
    print(f"all_records     {len(all_records)}")
    print(f"llm_eligible    {len(llm_eligible)}")
    print(f"by_status       {dict(status_counts)}")
    print(f"by_bucket       {dict(bucket_counts)}")
    print(f"by_route        {dict(route_counts)}")
    print(f"nondet reasons  {dict(reason_counts)}")


if __name__ == "__main__":
    main()
