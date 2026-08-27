#!/usr/bin/env python3
"""Build a BLINDED, randomized run manifest for the mechanics dry run.

Reads archive/dev_prompts.json and produces:
  archive/run_manifest.json  -- one entry per (case, condition), shuffled, each
                                with an opaque blind_id and the prompt text ONLY
                                (no case id, no condition, no ground truth).
  archive/blind_key.json      -- the sealed mapping blind_id -> (case, condition,
                                ground_truth). Consumed by scoring AFTER responses
                                exist; never shown to a reviewer.

The reviewer sees only the prompt behind a blind_id, so neither the condition
(A/B/C) nor the ground truth can leak into the response. A fixed seed makes the
shuffle reproducible for this development run; the confirmatory experiment will
draw fresh independent orderings per trial.
"""
import hashlib
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ARCH = os.path.join(HERE, "archive")
SEED = 20260827  # fixed for reproducible DEV run; not used for confirmatory trials


def main():
    cases = json.load(open(os.path.join(ARCH, "dev_prompts.json")))
    items = []
    for c in cases:
        for cond in ("A", "B", "C"):
            # opaque, order-independent blind id
            bid = "rev_" + hashlib.sha256(
                f"{SEED}|{c['id']}|{cond}".encode()).hexdigest()[:12]
            items.append({
                "blind_id": bid,
                "_case": c["id"], "_condition": cond,
                "_ground_truth": c["ground_truth"],
                "prompt": c["prompts"][cond],
            })
    random.Random(SEED).shuffle(items)

    manifest = [{"blind_id": it["blind_id"], "prompt": it["prompt"]} for it in items]
    key = {it["blind_id"]: {"case": it["_case"], "condition": it["_condition"],
                            "ground_truth": it["_ground_truth"]} for it in items}

    with open(os.path.join(ARCH, "run_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    with open(os.path.join(ARCH, "blind_key.json"), "w") as fh:
        json.dump(key, fh, indent=2, sort_keys=True)
    os.makedirs(os.path.join(ARCH, "responses"), exist_ok=True)

    print(f"blinded run manifest: {len(manifest)} reviewer tasks "
          f"({len(cases)} cases x 3 conditions), seed={SEED}")
    for m in manifest:
        print(f"  {m['blind_id']}")


if __name__ == "__main__":
    main()
