#!/usr/bin/env python3
"""Denylist / pattern matcher-kind mismatch detector gate.

The fixture encodes the Forminator forminator_allowed_mime_types() bypass plus
three discriminating negative controls, one for each way the bypass is broken.
Passing requires the detector to clear each control for the RIGHT reason, not
merely to fire once.

  D1 DETECT       denylist-vuln.js (EXACT guard + UNESCAPED regex consumer) ->
                  CANDIDATE_DENYLIST_PATTERN_BYPASS.
  D2 NORMALIZED   denylist-normalized.js (guard strips metachars before match)
                  -> SAFE_NORMALIZED_DENYLIST.
  D3 EXACT-CONS   denylist-exact-consumer.js (consumer matches exactly, no regex)
                  -> SAFE_EXACT_CONSUMER.
  D4 ESCAPED      denylist-escaped.js (consumer escapes token before regex)
                  -> SAFE_ESCAPED_CONSUMER.
  D5 NO FALSE +   exactly one CANDIDATE across the whole fixture.
  D6 GUARD KIND   the candidate's guard is classified EXACT and its consumer is
                  a regex with escaped=False (the precise mismatch).
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from denylist_bypass_verdict import derive  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "deny-out" / "raw"
F = derive(raw)["findings"]
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def by_file(substr):
    return next((f for f in F if substr in f["file"]), None)


vuln = by_file("denylist-vuln.js")
tooth("D1 vuln file -> CANDIDATE_DENYLIST_PATTERN_BYPASS",
      vuln is not None and vuln["verdict"] == "CANDIDATE_DENYLIST_PATTERN_BYPASS",
      str(vuln and vuln["verdict"]))

norm = by_file("denylist-normalized.js")
tooth("D2 normalized guard -> SAFE_NORMALIZED_DENYLIST",
      norm is not None and norm["verdict"] == "SAFE_NORMALIZED_DENYLIST",
      str(norm and norm["verdict"]))

exact = by_file("denylist-exact-consumer.js")
tooth("D3 exact consumer -> SAFE_EXACT_CONSUMER",
      exact is not None and exact["verdict"] == "SAFE_EXACT_CONSUMER",
      str(exact and exact["verdict"]))

esc = by_file("denylist-escaped.js")
tooth("D4 escaped consumer -> SAFE_ESCAPED_CONSUMER",
      esc is not None and esc["verdict"] == "SAFE_ESCAPED_CONSUMER",
      str(esc and esc["verdict"]))

cands = [f for f in F if f["verdict"] == "CANDIDATE_DENYLIST_PATTERN_BYPASS"]
tooth("D5 exactly one candidate in the fixture", len(cands) == 1, str(len(cands)))

tooth("D6 candidate mismatch: guard EXACT + regex consumer unescaped",
      vuln is not None and vuln["guard_match_kind"] == "EXACT"
      and vuln["consumer_is_regex"] is True and vuln["consumer_escaped"] is False,
      str(vuln and (vuln["guard_match_kind"], vuln["consumer_is_regex"], vuln["consumer_escaped"])))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"DENYLIST_BYPASS={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
