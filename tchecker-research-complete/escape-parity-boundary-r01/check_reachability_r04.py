#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- reachability gate (JavaScript + C/C++).

Covers the layer that sits on top of the frozen parser layer:

    stored file / archive / dump / database row
         -> the quoted-value parser
         -> decode / replace / re-encode
         -> a structured-data interpreter or database import routine

Both languages use one reducer over one fact schema. Every edge is real dataflow
computed by the engine.

  R1  C++  complete chain -> DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE
  R2  C++  same parser, result only logged -> candidate only, logging recorded
  R3  C++  immediate in-memory value -> no delayed source, not second-order
  R4  C++  scheduled entry point -> timing recorded as EVIDENCE, verdict unchanged
  R5  JS   complete chain -> DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE
  R6  JS   same transformation, result only logged -> candidate only
  R7  JS   delayed source but no consumer -> candidate, source recorded
  R8  JS   immediate in-memory -> no delayed source
  R9  JS   unresolved replacement callback -> chain abstains
  R10 JS   two parsers feeding one consumer -> AMBIGUOUS_CONSUMER_LINKAGE, neither promoted
  R11 a NEGATIVE parser is never promoted, whatever chain surrounds it
  R12 promotion requires BOTH a delayed source and a structured consumer
  R13 both languages share one chain vocabulary and one schema
  R14 the layer under-reports rather than over-reports where the engine cannot track a
      value (disclosed: C++ container-element flow)
  R15 reportable=false; no impact/severity/exploitability language
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from escape_parity_chain import derive, REACHABLE  # noqa: E402
from escape_parity_sites import CANDIDATE, NEGATIVE, ABSTAINED  # noqa: E402

cpp = derive(HERE / "fixtures_chain_cpp" / "raw")
js = derive(HERE / "fixtures_chain_js" / "raw")


def unit_of(f):
    return f["file"].split("/")[0] if "/" in f["file"] else f["unit"]


cpp_by = {}
for f in cpp["findings"]:
    cpp_by.setdefault(f["unit"], []).append(f)
js_by = {}
for f in js["findings"]:
    js_by.setdefault(unit_of(f), []).append(f)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def only(d, unit, cls=None):
    rows = [r for r in d.get(unit, []) if cls is None or r["classification"] == cls]
    return rows[0] if len(rows) == 1 else None


# --- C++ ---------------------------------------------------------------------
f1 = only(cpp_by, "c05_full_chain_string.cpp")
c1 = f1["chain"] if f1 else {}
tooth("R1 C++ stored dump -> one-position parser -> re-encode -> database import "
      "-> DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE",
      f1 is not None and f1["classification"] == REACHABLE
      and c1.get("status") == "ESTABLISHED"
      and len(c1.get("delayed_sources", [])) >= 1
      and len(c1.get("consumers", [])) == 1
      and c1["consumers"][0]["kind"] == "DATABASE_IMPORT"
      and c1.get("reasons") == [], str(c1))

f2 = only(cpp_by, "c06_log_only_string.cpp")
c2 = f2["chain"] if f2 else {}
tooth("R2 C++ same parser whose result only reaches logging -> candidate only, with the "
      "logging destination recorded as positive evidence",
      f2 is not None and f2["classification"] == CANDIDATE
      and c2.get("consumers") == []
      and len(c2.get("logging_only_consumers", [])) == 1
      and len(c2.get("delayed_sources", [])) >= 1, str(c2))

f3 = only(cpp_by, "c03_immediate.cpp")
tooth("R3 C++ immediate in-memory value -> no delayed source, not second-order",
      f3 is not None and f3["classification"] == CANDIDATE
      and f3["chain"]["delayed_sources"] == []
      and "NO_DELAYED_SOURCE_REACHES_PARSER" in f3["chain"]["reasons"], str(f3 and f3["chain"]))

f4 = only(cpp_by, "c04_scheduled_timing.cpp")
tooth("R4 C++ scheduled entry point -> execution timing recorded as EVIDENCE ONLY and "
      "the verdict is unchanged by it",
      f4 is not None
      and [t["kind"] for t in f4["execution_timing_evidence"]] == ["SCHEDULED_OR_DEFERRED"]
      and f4["classification"] == CANDIDATE
      and not any("SCHEDUL" in r or "TIMING" in r for r in f4["chain"]["reasons"]),
      str(f4 and f4["execution_timing_evidence"]))

# --- JavaScript --------------------------------------------------------------
f5 = only(js_by, "c07-full-chain")
c5 = f5["chain"] if f5 else {}
tooth("R5 JS stored dump -> decode -> replace -> re-encode -> structured interpreter "
      "-> DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE",
      f5 is not None and f5["classification"] == REACHABLE
      and c5.get("status") == "ESTABLISHED"
      and len(c5.get("delayed_sources", [])) == 1
      and [x["consumer_identity"] for x in c5.get("consumers", [])] == ["JSON.parse"],
      str(c5))

f6 = only(js_by, "c08-log-only")
c6 = f6["chain"] if f6 else {}
tooth("R6 JS same transformation whose result only reaches logging -> candidate only",
      f6 is not None and f6["classification"] == CANDIDATE
      and c6.get("consumers") == []
      and [x["consumer_identity"] for x in c6.get("logging_only_consumers", [])] == ["console.log"],
      str(c6))

f7 = only(js_by, "c05-delayed-source")
tooth("R7 JS delayed source reaches the parser but no consumer -> candidate, with the "
      "source recorded (resolved through a real import)",
      f7 is not None and f7["classification"] == CANDIDATE
      and len(f7["chain"]["delayed_sources"]) == 1
      and f7["chain"]["delayed_sources"][0]["resolution"] == "RESOLVED_IMPORT"
      and f7["chain"]["delayed_sources"][0]["api_identity"] == "fs.readFileSync",
      str(f7 and f7["chain"]["delayed_sources"]))

f8 = only(js_by, "c06-immediate")
tooth("R8 JS immediate in-memory transformation -> no delayed source",
      f8 is not None and f8["chain"]["delayed_sources"] == []
      and "NO_DELAYED_SOURCE_REACHES_PARSER" in f8["chain"]["reasons"], str(f8 and f8["chain"]))

f9 = only(js_by, "c10-unresolved-callback")
tooth("R9 JS unresolved replacement callback -> the chain abstains (the boundary rule "
      "still stands as a candidate)",
      f9 is not None and f9["classification"] == CANDIDATE
      and f9["chain"]["status"] == "ABSTAINED"
      and "UNRESOLVED_CALLBACK_IDENTITY" in f9.get("chain_abstention_reason", []),
      str(f9 and f9["chain"]))

f10 = js_by.get("c12-ambiguous-consumer", [])
tooth("R10 JS two parsers feeding one consumer -> AMBIGUOUS_CONSUMER_LINKAGE, neither "
      "promoted",
      len(f10) == 2
      and all(x["classification"] == CANDIDATE for x in f10)
      and all(x["chain"]["status"] == "ABSTAINED" for x in f10)
      and all("AMBIGUOUS_CONSUMER_LINKAGE" in x.get("chain_abstention_reason", []) for x in f10),
      str([x["chain"]["status"] for x in f10]))

# --- invariants --------------------------------------------------------------
negatives = [f for f in cpp["findings"] + js["findings"] if f["classification"] == NEGATIVE]
tooth("R11 a NEGATIVE parser is never promoted, whatever chain surrounds it",
      all(f["chain"]["status"] != "ESTABLISHED" for f in negatives)
      and all("NOT_A_CANDIDATE_NO_CHAIN_REQUIRED" in f["chain"]["reasons"] for f in negatives),
      f"n_negatives={len(negatives)}")

promoted = [f for f in cpp["findings"] + js["findings"] if f["classification"] == REACHABLE]
tooth("R12 promotion requires BOTH a delayed source and a structured consumer",
      len(promoted) == 2
      and all(f["chain"]["delayed_sources"] and f["chain"]["consumers"] for f in promoted)
      and all(f["chain"]["reasons"] == [] for f in promoted),
      f"promoted={[f['unit'] for f in promoted]}")

tooth("R13 both languages share one chain vocabulary and one schema",
      cpp["schema"] == js["schema"] == "escape-parity-boundary/chain-0.1"
      and cpp["classification_vocabulary"] == js["classification_vocabulary"] == [CANDIDATE, REACHABLE]
      and cpp["language"] == "C_CPP" and js["language"] == "JAVASCRIPT", "")

# R14: the vector-returning C++ fixtures have a delayed source reaching the parser but no
# consumer edge, because the engine does not track values through container elements.
# They must stay candidates -- under-reporting, never over-reporting.
vec = [only(cpp_by, u) for u in ("c01_full_chain.cpp", "c02_log_only.cpp",
                                 "c04_scheduled_timing.cpp")]
tooth("R14 where the engine cannot track a value (C++ container-element flow) the layer "
      "under-reports: the source edge is proven, the consumer edge is not, and the site "
      "stays a candidate rather than being promoted",
      all(v is not None and v["classification"] == CANDIDATE
          and len(v["chain"]["delayed_sources"]) >= 1
          and v["chain"]["consumers"] == [] for v in vec),
      str([(v["unit"], len(v["chain"]["delayed_sources"]), len(v["chain"]["consumers"]))
           for v in vec if v]))

banned = ("vulnerab", "exploit", "attacker", "severity", "cvss", "payload", "malicious")
blob = (json.dumps(cpp["findings"]) + json.dumps(js["findings"])).lower()
tooth("R15 reportable=false on every finding; no impact/severity/exploitability language",
      all(f["reportable"] is False for f in cpp["findings"] + js["findings"])
      and not [b for b in banned if b in blob], str([b for b in banned if b in blob]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "\n        <- " + detail[:350]))
print(f"ESCAPE_PARITY_REACHABILITY={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
