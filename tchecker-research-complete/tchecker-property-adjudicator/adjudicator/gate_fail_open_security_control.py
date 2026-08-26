#!/usr/bin/env python3
"""Frozen live-CPG gate for FAIL_OPEN_SECURITY_CONTROL R01."""
import json, sys
from pathlib import Path

fix = Path(__file__).resolve().parent.parent / "fixtures" / "fail_open_security_control"
rows = lambda name: [x.split("\t") for x in (fix / "raw" / name).read_text().splitlines() if x]
candidates = rows("fail_open_candidates.tsv")
audit = rows("fail_open_audit.tsv")
packet = json.loads((fix / "llm_input_1.json").read_text())
dispositions = [r[6] for r in audit]
checks = [
    ("F1 exactly one bounded candidate", len(candidates) == 1),
    ("F2 class remains separated and UNKNOWN", candidates[0][16:] == ["FAIL_OPEN_SECURITY_CONTROL", "UNKNOWN"]),
    ("F3 handler body resolved only through exact REF", candidates[0][15] == "ESTABLISHED_BY_EXACT_REF" and "return value || {}" in candidates[0][14]),
    ("F4 distinct handlers excluded", dispositions.count("EXCLUDED_DISTINCT_HANDLER") == 3),
    ("F5 one-handler chains excluded", dispositions.count("EXCLUDED_NO_REJECTION_HANDLER") == 6),
    ("F6 same-handler non-security use excluded", dispositions.count("EXCLUDED_NON_SECURITY_CONTEXT") == 1),
    ("F7 packet carries code and focused question", bool(packet["alternative"]["steps"][0]["definition_body"]) and "fail closed" in packet["QUESTION"]),
    ("F8 packet is advisory candidate evidence", packet["deterministic_status"] == "UNKNOWN" and packet["alternative"]["qualification"] == "CANDIDATE_SHAPE" and packet["answer_contract"]["note"].endswith("not a fact.")),
]
for name, ok in checks: print(("PASS  " if ok else "FAIL  ") + name)
passed = sum(ok for _, ok in checks)
print(f"FAIL_OPEN_SECURITY_CONTROL={passed}/{len(checks)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(checks) else "FAIL"))
sys.exit(0 if passed == len(checks) else 1)
