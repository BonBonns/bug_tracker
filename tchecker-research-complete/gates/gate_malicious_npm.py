#!/usr/bin/env python3
"""Malicious-npm install-exfil detector gate.

The fixture reproduces the lumen-pages-community (MAL-2026-14356) shape plus
three negative controls, each isolating ONE leg of the four-leg pattern.
Passing requires the co-occurrence logic to hold: no single leg alone convicts,
and each benign package is cleared for the correct reason.

  M1 DETECT        mal-pkg -> CANDIDATE_INSTALL_EXFIL.
  M2 LEGS          mal-pkg has all four legs: install hook, >=4 identifier kinds,
                   outbound request, and an exfil link inside the hook script.
  M3 RED FLAGS     mal-pkg manifest carries suspicious_version + placeholder_
                   description + no_library_entry.
  M4 NET-ONLY      benign-network (outbound, no identifiers) -> SAFE_NETWORK_
                   NO_IDENTIFIERS, never a candidate.
  M5 OSINFO-ONLY   benign-osinfo (identifiers, no exfil) -> SAFE_OSINFO_NO_EXFIL.
  M6 HOOK-ONLY     benign-postinstall (install hook, no harvest/exfil) ->
                   SAFE_INSTALL_HOOK_NO_EXFIL.
  M7 NO FALSE +    exactly one CANDIDATE_INSTALL_EXFIL across the fixture.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from malicious_npm_verdict import derive  # noqa: E402

root = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "mal-fixture"
raw = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "fixtures" / "mal-out" / "raw"
F = derive(root, raw)["findings"]
by = {f["dir"]: f for f in F}
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


mal = by.get("mal-pkg")
tooth("M1 mal-pkg -> CANDIDATE_INSTALL_EXFIL",
      mal is not None and mal["verdict"] == "CANDIDATE_INSTALL_EXFIL", str(mal and mal["verdict"]))

tooth("M2 all four legs present in mal-pkg",
      mal is not None and mal["install_hook"] and len(mal["identifier_kinds"]) >= 4
      and mal["outbound_count"] >= 1 and mal["exfil_in_install_hook"],
      str(mal and (bool(mal["install_hook"]), len(mal["identifier_kinds"]),
                   mal["outbound_count"], mal["exfil_in_install_hook"])))

tooth("M3 manifest red flags all present",
      mal is not None and set(mal["manifest_red_flags"]) ==
      {"suspicious_version", "placeholder_description", "no_library_entry"},
      str(mal and mal["manifest_red_flags"]))

n = by.get("benign-network")
tooth("M4 benign-network -> SAFE_NETWORK_NO_IDENTIFIERS",
      n is not None and n["verdict"] == "SAFE_NETWORK_NO_IDENTIFIERS", str(n and n["verdict"]))

o = by.get("benign-osinfo")
tooth("M5 benign-osinfo -> SAFE_OSINFO_NO_EXFIL",
      o is not None and o["verdict"] == "SAFE_OSINFO_NO_EXFIL", str(o and o["verdict"]))

h = by.get("benign-postinstall")
tooth("M6 benign-postinstall -> SAFE_INSTALL_HOOK_NO_EXFIL",
      h is not None and h["verdict"] == "SAFE_INSTALL_HOOK_NO_EXFIL", str(h and h["verdict"]))

cands = [f for f in F if f["verdict"].startswith("CANDIDATE_")]
tooth("M7 exactly four candidates in fixture (one per malicious shape)", len(cands) == 4, str(sorted(c["dir"] for c in cands)))

# --- new shapes ---
ev = by.get("eval-mal")
tooth("M8 eval-mal -> CANDIDATE_INSTALL_OBFUSCATED_EVAL (decode-fed eval in hook)",
      ev is not None and ev["verdict"] == "CANDIDATE_INSTALL_OBFUSCATED_EVAL"
      and ev["decode_eval"] and ev["eval_in_install_hook"], str(ev and ev["verdict"]))

evb = by.get("eval-benign")
tooth("M9 eval-benign (base64 as data, never eval'd) -> not a candidate",
      evb is not None and not evb["verdict"].startswith("CANDIDATE_") and not evb["decode_eval"],
      str(evb and evb["verdict"]))

cx = by.get("cpexec-mal")
tooth("M10 cpexec-mal -> CANDIDATE_INSTALL_CHILD_EXEC",
      cx is not None and cx["verdict"] == "CANDIDATE_INSTALL_CHILD_EXEC"
      and cx["exec_in_install_hook"], str(cx and cx["verdict"]))

cxb = by.get("cpexec-benign")
tooth("M11 cpexec-benign (runtime exec, no hook) -> SAFE_RUNTIME_CHILD_EXEC",
      cxb is not None and cxb["verdict"] == "SAFE_RUNTIME_CHILD_EXEC", str(cxb and cxb["verdict"]))

lm = by.get("launder-mal")
tooth("M12 launder-mal (harvest helper + send helper) -> CANDIDATE_INSTALL_EXFIL",
      lm is not None and lm["verdict"] == "CANDIDATE_INSTALL_EXFIL" and lm["laundered_exfil"],
      str(lm and lm["verdict"]))

lb = by.get("launder-benign")
tooth("M13 launder-benign (harvest helper, result stays local) -> SAFE_OSINFO_NO_EXFIL",
      lb is not None and lb["verdict"] == "SAFE_OSINFO_NO_EXFIL" and not lb["laundered_exfil"],
      str(lb and lb["verdict"]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"MALICIOUS_NPM={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
