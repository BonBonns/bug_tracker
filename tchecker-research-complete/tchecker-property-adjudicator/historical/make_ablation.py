#!/usr/bin/env python3
"""Body-context ablation builder.

Takes the SINGLE emails.js/normalizeEmail payload (B1, body supplied) and derives B0
(body withheld) from it so the two are byte-identical EXCEPT the body/evidence-availability
field and its corresponding wording. Both keep definition_status = ESTABLISHED (the identity
IS resolved in both); only body_supplied and the presence of the body text vary. Emits both
payloads plus a sha256 of each, and asserts the diff touches only the allowed fields.

Usage: python3 make_ablation.py <B1_llm_input.json> <out_dir>
"""
import copy, hashlib, json, sys
from pathlib import Path

B1_PATH = Path(sys.argv[1])
OUT = Path(sys.argv[2]); (OUT / "B0").mkdir(parents=True, exist_ok=True); (OUT / "B1").mkdir(parents=True, exist_ok=True)

b1 = json.load(open(B1_PATH))
assert b1["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["definition_status"] == "ESTABLISHED", \
    "ablation requires an ESTABLISHED definition in the base payload"
name = b1["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["callee_name"]
sem = b1["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["semantic_identity"]

# ---- B1: body supplied (as rendered). Ensure body_supplied=true is explicit. ----
b1["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["body_supplied"] = True

# ---- B0: identical, but withhold the body text + flip wording. ----
b0 = copy.deepcopy(b1)
b0["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["body_supplied"] = False
for r in b0["RELEVANT_CODE"]:
    if r.get("ref", "").endswith(".def"):
        r.pop("code", None)                     # withhold the body text
        r["body_supplied"] = False
        r["note"] = "definition identity ESTABLISHED but body withheld for this payload"
# withhold the resolved body wherever it appears in PATH_CODE_CONTEXT too (no leak)
for pth in b0.get("PATH_CODE_CONTEXT", []):
    for st in pth["steps"]:
        if st.get("definition_body") is not None:
            st["definition_body"] = None
            st["definition_body_withheld"] = True
# wording: identity established, body NOT supplied -> answer only from supplied evidence
base_q = (f"Does the on-path call `{name}` (semantic identity ESTABLISHED as {sem}) bound the "
          f"serialized size of the value, or can attacker influence remain effectively unbounded?")
b0["QUESTION"] = (base_q + f" The implementation body of `{name}` was NOT supplied in this payload. "
                  f"Answer ONLY from the supplied evidence; return UNKNOWN if the body is required and "
                  f"not available. Do NOT infer behavior from the function name.")
# B1 wording already references the supplied implementation; keep it.

# ---- assert: B0 and B1 differ ONLY in the allowed fields ----
def strip_allowed(p):
    q = copy.deepcopy(p)
    q["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"].pop("body_supplied", None)
    q["QUESTION"] = "<<Q>>"
    for r in q["RELEVANT_CODE"]:
        if r.get("ref", "").endswith(".def"):
            r.pop("code", None); r.pop("body_supplied", None); r.pop("note", None)
    for pth in q.get("PATH_CODE_CONTEXT", []):
        for st in pth["steps"]:
            st.pop("definition_body", None); st.pop("definition_body_withheld", None)
    return json.dumps(q, sort_keys=True)

assert strip_allowed(b0) == strip_allowed(b1), "B0/B1 differ outside the allowed body/wording fields!"

(OUT / "B0" / "llm_input.json").write_text(json.dumps(b0, indent=2))
(OUT / "B1" / "llm_input.json").write_text(json.dumps(b1, indent=2))
h0 = hashlib.sha256((OUT / "B0" / "llm_input.json").read_bytes()).hexdigest()
h1 = hashlib.sha256((OUT / "B1" / "llm_input.json").read_bytes()).hexdigest()
(OUT / "PAYLOAD_HASHES.txt").write_text(f"B0 sha256 {h0}\nB1 sha256 {h1}\n")
print("single-variable ablation built and frozen.")
print(f"  B0 (body withheld) sha256 {h0[:16]}")
print(f"  B1 (body supplied) sha256 {h1[:16]}")
print("  invariant: B0 and B1 differ ONLY in body text + body_supplied + question wording.")
