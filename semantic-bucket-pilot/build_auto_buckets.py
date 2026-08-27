#!/usr/bin/env python3
"""Close the loop: run TChecker's automatic bucket layer on the real frozen-
scanner output for each candidate case, emit the machine-derived record, and
write machine-derived prompt sources (facts, highlighted operation, C category +
focused question) that generate_prompts.py consumes.

The ONLY human-supplied input here is (a) which fact file + function each case
lives in, and (b) the independently-verified bucket ground truth used for the
agreement check. The bucket, unresolved property, route, established facts,
highlighted operation, and C question all come from `tools/bucket_router.py`
(the scanner), not from a person preparing the experiment.

Outputs:
  auto_buckets/<id>.record.json     the raw auto-emitted bucket record
  sources_auto/<id>.facts.txt       established facts, machine-derived
  sources_auto/<id>.meta.json       highlighted op + auto category + auto question
Prints the auto-bucket vs verified-bucket agreement.

Run from the pilot dir. Requires the cached real cpp.json fact files.
"""
import json
import pathlib
import sys

TCHECKER_TOOLS = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tools"
sys.path.insert(0, TCHECKER_TOOLS)
from bucket_router import route_factfile, render_for_condition_c  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent

# Human supplies ONLY: fact file, function to locate the candidate, and the
# independently-verified bucket (for the agreement check -- NOT fed into C).
CASES = {
    "SB-01": {"factfile": "/tmp/cve-2019-17006/patched/scan/work/cpp.json",
              "function": "rsa_FormatOneBlock", "verified_bucket": "relationship_unresolved"},
    "SB-02": {"factfile": "/tmp/mjpg-cve-huff/patched/scan/work/cpp.json",
              "function": "flush_bits", "verified_bucket": "relationship_unresolved"},
    "SB-07": {"factfile": "/tmp/cve-2019-11745/vuln/scan/work/cpp.json",
              "function": "nsc_pbe_key_gen", "verified_bucket": "relationship_unresolved"},
}


def main():
    (ROOT / "auto_buckets").mkdir(exist_ok=True)
    (ROOT / "sources_auto").mkdir(exist_ok=True)
    agree = 0
    for cid, c in CASES.items():
        recs = [r for r in route_factfile(c["factfile"]) if r["function"] == c["function"]]
        if not recs:
            print(f"{cid}: NO auto candidate in {c['function']} -- FAIL")
            continue
        r = recs[0]
        # GENERATOR GUARD: the final experiment must reject any record whose
        # bucket did not come from an explicit producer reason code. A
        # candidate-presence fallback is NOT eligible for the A/B/C corpus.
        if r.get("reason_source") != "explicit_producer_reason":
            print(f"{cid}: REJECTED for A/B/C -- reason_source={r.get('reason_source')} "
                  f"(producer reason layer not implemented; not corpus-eligible)")
            continue
        ok = r["uncertainty_bucket"] == c["verified_bucket"]
        agree += ok

        (ROOT / "auto_buckets" / f"{cid}.record.json").write_text(json.dumps(r, indent=2) + "\n")

        # machine-derived established facts (Condition B/C body)
        facts = "\n".join(f"- {f}" for f in r["established_facts"])
        (ROOT / "sources_auto" / f"{cid}.facts.txt").write_text(facts + "\n")

        # machine-derived highlighted operation + auto C category/question
        rc = render_for_condition_c(r)
        highlighted = f"the {r['subclass']} write at {r['file']}:{r['line']} in {r['function']}"
        meta = {"case_id": cid, "scanner_uncertainty_category": r["uncertainty_bucket"],
                "routable": True, "highlighted_operation": highlighted,
                "uncertainty_category": rc["uncertainty_category"],
                "focused_question": rc["focused_question"],
                "auto_candidate_id": r["candidate_id"],
                "auto_unresolved_property": r["unresolved_property"],
                "auto_recommended_route": r["recommended_route"]}
        (ROOT / "sources_auto" / f"{cid}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")

        print(f"{cid}: auto_bucket={r['uncertainty_bucket']} verified={c['verified_bucket']} "
              f"{'AGREE' if ok else 'DISAGREE'}  id={r['candidate_id']} "
              f"prop={r['unresolved_property']} route={r['recommended_route']}")
    print(f"\nAUTO-BUCKET AGREEMENT WITH VERIFIED GROUND TRUTH: {agree}/{len(CASES)}")
    print("Machine-derived sources written to sources_auto/. NOTE: these carry the "
          "code separately -- sources_auto holds only facts+meta; the .code.txt "
          "still comes from the sanitized extract. For the FINAL experiment, "
          "generate_prompts.py must read facts+meta from sources_auto/ (machine-"
          "derived) rather than the hand-written sources/.")


if __name__ == "__main__":
    main()
