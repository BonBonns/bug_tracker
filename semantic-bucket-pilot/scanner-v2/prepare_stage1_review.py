#!/usr/bin/env python3
"""Stage 1 preparation — produce two independently randomized, BLINDED reviewer
bundles from the frozen neutral reference packet, plus the labeling schema each
reviewer fills. Produces NO labels (independent human judgment cannot be
manufactured). A/B/C prompts are NOT generated here.

Outputs under study/review/:
  reviewer_1_bundle.jsonl   438 neutral cases, randomized order (seed r1)
  reviewer_2_bundle.jsonl   438 neutral cases, DIFFERENT randomized order (seed r2)
  LABELING_INSTRUCTIONS.md  the task + schema + decision rules
  bundles_FROZEN.json       seeds, per-bundle sha256, blinding assertion
"""
import hashlib
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study", "review")
PACKET = os.path.join(HERE, "study", "stage1_labeling_packet.jsonl")

# Forbidden in a blinded bundle: study/scanner metadata only — the condition
# assignment, bucket, route, revision side, or model output. NOT generic English
# words (e.g. "condition"/"prediction") that legitimately occur in C source, which
# the reviewer sees anyway.
FORBIDDEN = ["recommended_route", "v1_route", "v2_route",
             "additional_evidence_required", "semantic_relationship_review",
             "range_arithmetic_review", "deterministic_complete", "uncertainty_bucket",
             "unresolved_property", "established_property", "llm_eligible", "_v2_",
             "pre_patch", "post_patch", "revision_side", "stack_fixed_array"]

# schema fields the reviewer fills (left null in the bundle)
LABEL_TEMPLATE = {
    "evidence_reference_conclusion": None,   # safe | vulnerable | unresolved
    "established_facts_valid": None,         # valid | invalid | unresolved
    "program_outcome": None,                 # safe | vulnerable | not_established
    "relationship_answer": None,             # established | contradicted | unresolved
    "rationale": None,                       # free text
    "supporting_evidence": None,             # which packet fields were load-bearing
    "reviewer_confidence": None,             # high | medium | low
}


def blinded_case(p):
    """Reviewer-facing case: the neutral evidence only (drop scan family / anything
    that is not the shared reference evidence)."""
    return {
        "instance_id": p["packet_instance_id"],
        "family_ref": p["packet_family_id"],
        "sibling_instance_ids": p["sibling_instance_ids"],
        "operation": p["operation"],
        "destination_capacity_evidence": p["destination_capacity_evidence"],
        "write_length": p["write_length"],
        "enclosing_guards": p["enclosing_guards"],
        "reachability_evidence": p["reachability_evidence"],
        "function_source": p["function_source"],
    }


def sha_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def main():
    os.makedirs(OUT, exist_ok=True)
    packet = [json.loads(l) for l in open(PACKET)]
    ids = [p["packet_instance_id"] for p in packet]
    assert len(ids) == len(set(ids)) == 438, "packet must be 438 distinct instances"

    bundles = {}
    for rid, seed_key in (("reviewer_1", "stage1-r1"), ("reviewer_2", "stage1-r2")):
        seed = int(hashlib.sha256(seed_key.encode()).hexdigest(), 16) % (2**32)
        order = list(range(len(packet)))
        random.Random(seed).shuffle(order)
        path = os.path.join(OUT, f"{rid}_bundle.jsonl")
        with open(path, "w") as fh:
            for disp, idx in enumerate(order):
                row = {"display_order": disp, "reviewer_id": rid,
                       "case": blinded_case(packet[idx]),
                       "label": dict(LABEL_TEMPLATE)}
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        bundles[rid] = {"seed_key": seed_key, "seed": seed, "sha256": sha_file(path),
                        "first_id": json.loads(open(path).readline())["case"]["instance_id"]}

    # blinding assertion on both bundles
    for rid in bundles:
        blob = open(os.path.join(OUT, f"{rid}_bundle.jsonl")).read()
        leaked = sorted({t for t in FORBIDDEN if t in blob})
        assert not leaked, f"{rid} bundle leaks forbidden tokens: {leaked}"

    # the two orders must differ (independent randomization)
    o1 = [json.loads(l)["case"]["instance_id"] for l in open(os.path.join(OUT, "reviewer_1_bundle.jsonl"))]
    o2 = [json.loads(l)["case"]["instance_id"] for l in open(os.path.join(OUT, "reviewer_2_bundle.jsonl"))]
    assert set(o1) == set(o2) == set(ids), "bundles must cover the same 438 ids"
    assert o1 != o2, "the two bundle orders must differ"

    frozen = {"instances": len(ids), "bundles": bundles,
              "blinding": "no condition/bucket/route/revision-side/model output (asserted)",
              "note": "reviewer bundles only; NO labels produced; A/B/C not generated."}
    with open(os.path.join(OUT, "bundles_FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True)

    _write_instructions()
    print(f"438 cases -> 2 blinded reviewer bundles (independent random orders)")
    print(f"  reviewer_1 first id: {bundles['reviewer_1']['first_id']}")
    print(f"  reviewer_2 first id: {bundles['reviewer_2']['first_id']}")
    print(f"  orders differ: {o1 != o2}   blinding: PASS")
    print(f"artifacts under {OUT}/  (bundles, instructions, freeze). NO labels, no A/B/C.")


def _write_instructions():
    md = """# Stage 1 labeling — reviewer instructions

You are one of two **independent** reviewers. Do not confer with the other reviewer.
Label every case in your bundle (`reviewer_N_bundle.jsonl`) by filling the `label`
object in each row. Return the completed file as `reviewer_N_labels.jsonl`.

You see a **neutral reference packet**: shared code + established scanner facts. You
do NOT see which review condition, bucket, route, or repository side a case belongs
to, and you see no model output. Judge each case on the evidence shown.

## Fill these fields per case

- `evidence_reference_conclusion`: **safe | vulnerable | unresolved** — the conclusion
  the packet evidence supports. If the evidence does not establish either outcome,
  answer **unresolved** (do not guess). This is the primary scored field.
- `established_facts_valid`: **valid | invalid | unresolved** — is the packet's stated
  capacity / write-length fact actually correct for this code? If a load-bearing fact
  is wrong, mark **invalid** (the case is then excluded as an upstream evidence
  error); if you cannot tell, **unresolved**.
- `program_outcome`: **safe | vulnerable | not_established** — your best judgment of
  the code's real status (reported separately, not scored). May differ from the
  evidence-relative conclusion.
- `relationship_answer`: **established | contradicted | unresolved** — did the packet
  establish the length/capacity relationship, contradict it, or leave it open?
- `rationale`: free text — the reasoning for your conclusion.
- `supporting_evidence`: which packet fields were load-bearing (e.g. capacity,
  write_length, guard, reachability, function_source).
- `reviewer_confidence`: **high | medium | low**.

## Rules

- Do not assume an operation is vulnerable because it "looks like" a known bug; label
  from the evidence shown.
- `unresolved` is a first-class answer; use it when the evidence is insufficient.
- Related cases share a `family_ref` and appear as `sibling_instance_ids`; you may
  compare them, but label each case on its own.
- Return every instance_id in your bundle, exactly once.

After both reviewers return files, an import validator checks completeness and
independence, and a disagreement file is produced for the frozen tie-break reviewer.
"""
    open(os.path.join(OUT, "LABELING_INSTRUCTIONS.md"), "w").write(md)


if __name__ == "__main__":
    main()
