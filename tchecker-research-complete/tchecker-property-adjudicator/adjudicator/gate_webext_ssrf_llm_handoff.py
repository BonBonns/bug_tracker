#!/usr/bin/env python3
"""Frozen live-run gate for WebExtension SSRF semantic handoff."""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "webext_ssrf_transform"
RAW = FIX / "raw"
packet = json.loads((FIX / "llm_input_1.json").read_text())
rows = lambda n: [x.split("\t") for x in (RAW / n).read_text().splitlines() if x.strip()]
checks = [
    ("H1 property remains OPEN", rows("property_outcome.tsv")[0][2] == "OPEN"),
    ("H2 external-message family preserved", rows("source_facts.tsv")[0][3] == "WEBEXT_EXTERNAL_MESSAGE_INPUT"),
    ("H3 two ordered unresolved transforms", [r[4] for r in rows("transform_identity.tsv")] == ["rewriteTarget", "normalizeDestination"]),
    ("H4 canonical code context covers source/steps/sink", len(rows("path_code_context.tsv")) == 4),
    ("H5 packet targets first unresolved transform", packet["unresolved_subject"]["call_node_id"] == "30064771074"),
    ("H6 source statement is present", bool(packet["alternative"]["origin"]["source_containing_statement"])),
    ("H7 every transform callsite and statement is present", all(s["callsite_code"] and s["containing_statement"] for s in packet["alternative"]["steps"])),
    ("H8 sink expression and statement are present", bool(packet["alternative"]["sink"]["expression"] and packet["alternative"]["sink"]["containing_statement"])),
    ("H9 question is SSRF-host-scoped and permits UNKNOWN", "HOST" in packet["QUESTION"] and "UNKNOWN" in packet["QUESTION"]),
    ("H10 LLM output remains advisory", packet["answer_contract"]["note"].endswith("not a fact.")),
]
for name, ok in checks: print(("PASS  " if ok else "FAIL  ") + name)
passed = sum(ok for _, ok in checks)
print(f"WEBEXT_SSRF_LLM_HANDOFF={passed}/{len(checks)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(checks) else "FAIL"))
sys.exit(0 if passed == len(checks) else 1)
