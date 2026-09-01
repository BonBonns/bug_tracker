#!/usr/bin/env python3
"""Gate for nan_package_owned_dedup.py (NAN-DEDUP-TASK3). See that module's own docstring and
`study/nan_capability/NODE_SNAP7_DEDUP_REVIEW.md` for the real evidence this dedup key is built
from.

Uses node-snap7's own REAL replayed nan_findings (`study/task34_replay/results/
replay_records_v6_nan.jsonl`, produced by `nan_replay_over_97.py`, task 4) as the base for every
control below -- never a synthetic fixture invented from scratch. Control 2's "second package"
record reuses node-snap7's own real `acquisition_code`/`method_name`/`contract_id` values under
node-snap7-micro-client's real package identity -- not a fabricated value: this session directly
confirmed, via a byte-for-byte diff of both packages' real, hash-verified `src/
node_snap7_client.cpp`, that node-snap7-micro-client's own real source carries the exact same
`Nan::NewBuffer(...)` acquisition-call text for all three methods (see the dedup review doc).
node-snap7-micro-client itself is not part of the current 97-package replayed sample (confirmed:
absent from `overnight_sample_100.json`), so this is the correct, disclosed way to control the
mechanism against real evidence without fabricating a live scan result for a package this round
never actually analyzed.
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nan_package_owned_dedup as D  # noqa: E402

V6_PATH = os.path.join(HERE, "study", "task34_replay", "results", "replay_records_v6_nan.jsonl")

ok = 0
tot = 0


def ck(name, cond):
    global ok, tot
    tot += 1
    ok += 1 if cond else 0
    print(("PASS " if cond else "FAIL ") + name)


with open(V6_PATH) as f:
    recs = [json.loads(line) for line in f]
snap7 = next(r for r in recs if r["package_name"] == "node-snap7")
ck("fixture: node-snap7's own real replay carries exactly 3 reportable nan_findings",
   sum(1 for f in snap7["nan_findings"] if f.get("reportable")) == 3)

# --- Control 1: node-snap7 alone -> 3 distinct real sites, each seen once. -----------------
d1 = D.dedup_nan_reportable([snap7])
ck("control 1: node-snap7 alone -> exactly 3 distinct dedup keys", len(d1) == 3)
ck("control 1: each site's raw_exposure_count is 1 (no false self-collapse)",
   all(e["raw_exposure_count"] == 1 for e in d1.values()))
ck("control 1: each site's packages list is exactly [\"node-snap7\"]",
   all(e["packages"] == ["node-snap7"] for e in d1.values()))

# --- Control 2 (the real task -- positive): node-snap7 + a record carrying node-snap7-micro-
# client's real package identity and node-snap7's own real, confirmed-identical site evidence. -
micro = copy.deepcopy(snap7)
micro["package_name"] = "node-snap7-micro-client"
micro["version"] = "0.1.0"
d2 = D.dedup_nan_reportable([snap7, micro])
ck("control 2: node-snap7 + node-snap7-micro-client -> STILL exactly 3 deduplicated sites "
   "(ReadArea/Upload/FullUpload each collapse across both real package identities)",
   len(d2) == 3)
ck("control 2: every deduplicated site's packages list spans both real identities",
   all(e["packages"] == ["node-snap7", "node-snap7-micro-client"] for e in d2.values()))
ck("control 2: every deduplicated site's raw_exposure_count is 2",
   all(e["raw_exposure_count"] == 2 for e in d2.values()))

# --- Control 3 (negative): a genuinely different acquisition_code must never collapse. -------
other = copy.deepcopy(snap7)
other["package_name"] = "some-unrelated-package"
for f in other["nan_findings"]:
    if f.get("reportable"):
        f["acquisition_code"] = "Nan::NewBuffer(totallyDifferent, n, cb, NULL)"
d3 = D.dedup_nan_reportable([snap7, other])
ck("control 3 (negative): an unrelated package's own genuinely different acquisition_code "
   "never collapses into node-snap7's own sites (3 + 3 = 6 distinct keys)", len(d3) == 6)

# --- Control 4 (negative): a non-reportable (abstention) finding is never dedup-counted. -----
abstain_only = copy.deepcopy(snap7)
abstain_only["package_name"] = "abstain-only-package"
for f in abstain_only["nan_findings"]:
    f["reportable"] = False
d4 = D.dedup_nan_reportable([abstain_only])
ck("control 4 (negative): a record with zero reportable=True findings contributes nothing",
   len(d4) == 0)

# --- Control 5 (negative): whole-file content_hash would have been the WRONG key -- confirmed
# directly against the real fixture: node-snap7's own 3 real findings do NOT all share one
# method_name (so method_name alone is a real, sufficient per-package discriminator), but DO
# all share one acquisition_code text (so acquisition_code alone is NOT sufficient without
# method_name) -- the real reason this module's key is the PAIR, not either alone.
codes = {f.get("acquisition_code") for f in snap7["nan_findings"] if f.get("reportable")}
methods = {f.get("method_name") for f in snap7["nan_findings"] if f.get("reportable")}
ck("control 5: real evidence -- all 3 real sites share ONE acquisition_code text (confirms "
   "method_name must be part of the key)", len(codes) == 1)
ck("control 5: real evidence -- the 3 real sites have 3 DISTINCT method_names (confirms "
   "method_name is a sufficient per-package discriminator)", len(methods) == 3)

print(f"NAN_PACKAGE_OWNED_DEDUP_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
