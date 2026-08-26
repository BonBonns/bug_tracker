#!/usr/bin/env python3
"""LLM-input vulnerability detector gate (OWASP LLM01 + LLM02).

Fixture: two vuln shapes + three signal-isolating controls.
  L1 OUTPUT     llm-eval-vuln (model output -> eval) -> CANDIDATE_INSECURE_LLM_OUTPUT.
  L2 INJECTION  llm-sysinject-vuln (request -> system role) -> CANDIDATE_PROMPT_INJECTION.
  L3 OUTPUT-SAFE llm-output-safe (output parsed & returned as data, no dangerous
                 sink) -> no candidate.
  L4 USER-ROLE  llm-userrole-safe (static system prompt, user data in user role
                 only) -> no candidate. The tooth that stops flagging every LLM
                 call that includes request data.
  L5 NO-LLM     llm-no-llm (eval present but NOT model-fed) -> no candidate. The
                 tooth that stops flagging every eval.
  L6 NO FALSE + exactly two candidates across the fixture.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from llm_input_verdict import derive  # noqa: E402

raw = (Path(sys.argv[1]) if len(sys.argv) > 1
       else HERE.parent / "fixtures" / "llm_input-out" / "raw")
F = derive(raw)["findings"]
cand_by_pkg = {}
for f in F:
    if f["verdict"].startswith("CANDIDATE"):
        cand_by_pkg.setdefault(f["package"], []).append(f)
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


ev = cand_by_pkg.get("llm-eval-vuln", [])
tooth("L1 llm-eval-vuln -> CANDIDATE_INSECURE_LLM_OUTPUT",
      any(f["verdict"] == "CANDIDATE_INSECURE_LLM_OUTPUT" for f in ev), str(ev))

inj = cand_by_pkg.get("llm-sysinject-vuln", [])
tooth("L2 llm-sysinject-vuln -> CANDIDATE_PROMPT_INJECTION",
      any(f["verdict"] == "CANDIDATE_PROMPT_INJECTION" for f in inj), str(inj))

tooth("L3 llm-output-safe -> no candidate (output as data)",
      "llm-output-safe" not in cand_by_pkg, str(cand_by_pkg.get("llm-output-safe")))

tooth("L4 llm-userrole-safe -> no candidate (static system, user role)",
      "llm-userrole-safe" not in cand_by_pkg, str(cand_by_pkg.get("llm-userrole-safe")))

tooth("L5 llm-no-llm -> no candidate (eval not model-fed)",
      "llm-no-llm" not in cand_by_pkg, str(cand_by_pkg.get("llm-no-llm")))

total = sum(len(v) for v in cand_by_pkg.values())
tooth("L6 exactly two candidates in fixture", total == 2, str(total))

tooth("L7 Twilio messages.create NOT flagged as LLM (import+model disambiguation)",
      "llm-twilio-safe" not in cand_by_pkg, str(cand_by_pkg.get("llm-twilio-safe")))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"LLM_INPUT={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
