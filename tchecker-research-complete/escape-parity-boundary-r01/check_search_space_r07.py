#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- search-space gate (R07).

The reachability layer reported `NO_STRUCTURED_TEXT_CONSUMER_REACHED` whenever a
candidate's chain reached no structured-text consumer. That reads as "the
parser's output was traced and reaches no structured interpreter". On the one
real chain in the corpus it meant something much weaker: the analysed Gecko
surface contains **zero** consumers of the modelled kinds -- Gecko has its own
JSON and XML parsers and does not call json_tokener_parse, cJSON_Parse,
xmlReadMemory or sqlite3_exec -- so nothing of that kind could have been reached
by any code whatsoever.

A negative that could never have come out otherwise is not a finding about the
code. It is a finding about the model's coverage of the code, and the two must
not share a reason string. This is the same defect the parser layer had at R01,
where a control that produced no record at all made "negative" and "never
looked" indistinguishable.

R07 records the search space on every chain and splits the reasons:

    NO_SOURCE_API_MODELLED_IN_UNIT           the model does not cover this unit
    NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT  the model does not cover this unit
    NO_DELAYED_SOURCE_REACHES_PARSER         flows were computed, none connected
    NO_STRUCTURED_TEXT_CONSUMER_REACHED      flows were computed, none connected

It also stops claiming either when the parser has no call site at all: with
nothing to trace from, neither statement means anything.

  C1 a unit with no modelled structured consumer says so, and does not claim a
     traced negative
  C2 a unit that HAS modelled sources and consumers still reports the traced
     negative when flows genuinely do not connect
  C3 every candidate chain carries its search space
  C4 a proven full chain still establishes, in both languages
  C5 no chain claims a traced negative while the parser is never called
  C6 reportable=false, and no chain record carries impact or severity language
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "parser_model"))
from escape_parity_chain import (  # noqa: E402
    derive, REACHABLE, NO_SOURCE_MODELLED, NO_CONSUMER_MODELLED,
)
from escape_parity_sites import CANDIDATE  # noqa: E402

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def candidates(raw, lang):
    return [f for f in derive(HERE / raw, lang)["findings"]
            if f["classification"] == CANDIDATE]


# The real Gecko facts are the evidence for C1: a 1,528-file C++ unit with two
# resolved sources and zero structured consumers.
GECKO = "study/bounty_corpus/results_r07/mozilla-gecko-dev-prefix/raw_c_cpp"
gecko = candidates(GECKO, "C_CPP")
g = gecko[0] if len(gecko) == 1 else None
tooth("C1 a unit with no modelled structured consumer says so",
      g is not None
      and g["chain"]["search_space"]["structured_consumers_in_unit"] == 0
      and NO_CONSUMER_MODELLED in g["chain"]["reasons"]
      and "NO_STRUCTURED_TEXT_CONSUMER_REACHED" not in g["chain"]["reasons"],
      json.dumps(g["chain"]["reasons"], sort_keys=True) if g else "expected 1 candidate")

# The chain fixtures are the evidence for C2: real sources and real consumers
# present, one chain establishing and others not.
for raw, lang in (("fixtures_chain_js/raw", "JAVASCRIPT"),
                  ("fixtures_chain_cpp/raw", "C_CPP")):
    cands = candidates(raw, lang)
    traced = [f for f in cands
              if f["chain"]["search_space"]["structured_consumers_in_unit"] > 0
              and f["chain"]["search_space"]["parser_call_sites"] > 0
              and "NO_STRUCTURED_TEXT_CONSUMER_REACHED" in f["chain"]["reasons"]]
    vacuous = [f for f in cands if NO_CONSUMER_MODELLED in f["chain"]["reasons"]]
    tooth("C2 %s reports a traced negative where the model does cover the unit"
          % lang.lower(),
          len(traced) > 0 and not vacuous,
          "%d traced, %d vacuous, of %d candidates"
          % (len(traced), len(vacuous), len(cands)))

allc = gecko + candidates("fixtures_chain_js/raw", "JAVASCRIPT") \
             + candidates("fixtures_chain_cpp/raw", "C_CPP")
REQUIRED = ("resolved_sources_in_unit", "structured_consumers_in_unit",
            "parser_call_sites", "flow_edges_in_unit")
tooth("C3 every candidate chain carries its search space",
      len(allc) > 0 and all(all(k in f["chain"].get("search_space", {})
                                for k in REQUIRED) for f in allc),
      "%d candidate chain(s)" % len(allc))

est = {}
for raw, lang in (("fixtures_chain_js/raw", "JAVASCRIPT"),
                  ("fixtures_chain_cpp/raw", "C_CPP")):
    est[lang] = sum(1 for f in derive(HERE / raw, lang)["findings"]
                    if f["classification"] == REACHABLE)
tooth("C4 a proven full chain still establishes, in both languages",
      est.get("JAVASCRIPT", 0) == 1 and est.get("C_CPP", 0) == 1, str(est))

TRACED = ("NO_DELAYED_SOURCE_REACHES_PARSER", "NO_STRUCTURED_TEXT_CONSUMER_REACHED")
bad_uncalled = [f for f in allc
                if f["chain"]["search_space"]["parser_call_sites"] == 0
                and any(r in TRACED for r in f["chain"]["reasons"])]
tooth("C5 no traced negative is claimed while the parser is never called",
      not bad_uncalled,
      "; ".join("%s L%s %s" % (f["file"], f["line"], f["chain"]["reasons"])
                for f in bad_uncalled[:3]))

BANNED = ("vulnerab", "exploit", "severity", "attacker", "impact",
          "critical", "cve", "payload")
bad = []
for f in allc:
    blob = json.dumps(f).lower()
    if f.get("reportable") is not False:
        bad.append("%s: reportable is not false" % f["file"])
    for w in BANNED:
        if w in blob:
            bad.append("%s: %r" % (f["file"], w))
tooth("C6 reportable=false and no impact or severity language", not bad,
      "; ".join(bad[:4]))

width = max(len(n) for n, _, _ in results)
for name, ok, detail in results:
    print("%-*s  %s" % (width, name, "PASS" if ok else "FAIL"))
    if not ok and detail:
        print("%s  %s" % (" " * width, detail))
passed = sum(1 for _, ok, _ in results if ok)
print("\nESCAPE_PARITY_SEARCH_SPACE=%d/%d" % (passed, len(results)))
print("PROMOTION_GATE=%s" % ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
