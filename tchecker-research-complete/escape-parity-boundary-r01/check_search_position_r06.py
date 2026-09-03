#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- search-established position gate (R06), JS + C/C++.

Up to R05 the two halves of a one-position rule were paired only when the quote
half was a COMPARISON. Scanners routinely establish "position p holds a quote"
with a search instead --

    let p = input.indexOf(quoteChar, cursor);   //  JavaScript
    size_t p = s.find(QUOTE, cursor);           //  C++

-- and a rule written that way was never paired, so `input[p - 1] === ESCAPE`
went unclassified even when both delimiters resolved.

R06 lets a resolved search position stand in for a quote comparison at offset
zero on the same base and position variable.

The risk this gate exists to hold down is the opposite error. A FORWARD look at
a search position (`input[p + 1] === QUOTE`) is the doubled-delimiter idiom: it
consumes the pair and is therefore parity-correct. Treating it as a
one-position rule would be a false positive on correct code, so only BACKWARD
offsets pair, and D14 is what keeps that honest.

  S1  search position + backward one-position check -> candidate, both languages
  S2  search position + forward doubling check -> never a candidate
  S3  a search position with an unresolved delimiter reaches no verdict
  S4  a search-established site is recorded, and carries its resolution
  S5  every pre-R06 per-site verdict is unchanged
  S6  reportable=false, and no record carries impact or severity language
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "parser_model"))
from escape_parity_sites import (  # noqa: E402
    derive, CANDIDATE, NEGATIVE, ABSTAINED,
    SINGLE_POSITION_INDEX_CHECK, UNRESOLVED_DELIMITER_IDENTITY,
)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


js = derive(HERE / "fixtures_delim" / "raw", "JAVASCRIPT")["findings"]
cpp = derive(HERE / "fixtures_delim_cpp" / "raw", "C_CPP")["findings"]


def unit(findings, prefix):
    return [f for f in findings if f["file"].startswith(prefix)]


# ------------------------------------------------------------------- S1
# d08/e05 each establish the quote position with THREE separate search calls:
# one before the loop, one inside the same `if` as the escape check, and one
# in a sibling statement of the loop body. Only the one actually nested inside
# the escape check's guard is part of the boundary rule -- the loop is not a
# decision, so the other two correctly have no rule of their own (R09: pairing
# on "reachable via any loop-body ancestor" was a confirmed false positive
# that made all three candidates; see PARSER_MODEL scope-fix notes).
d08, e05 = unit(js, "d08-"), unit(cpp, "e05")
d08_cand = [f for f in d08 if f["classification"] == CANDIDATE]
e05_cand = [f for f in e05 if f["classification"] == CANDIDATE]
tooth("S1 search position + backward one-position check -> candidate (JS and C/C++), "
      "and only the search call actually inside the escape check's guard qualifies",
      len(d08) == 3 and len(e05) == 3
      and len(d08_cand) == 1 and len(e05_cand) == 1
      and d08_cand[0]["boundary_rule"] == SINGLE_POSITION_INDEX_CHECK
      and e05_cand[0]["boundary_rule"] == SINGLE_POSITION_INDEX_CHECK
      and all(f["classification"] == NEGATIVE for f in d08 + e05 if f not in d08_cand + e05_cand),
      "js=%s cpp=%s" % ([f["classification"] for f in d08],
                        [f["classification"] for f in e05]))

# ------------------------------------------------------------------- S2
d09, e06 = unit(js, "d09-"), unit(cpp, "e06")
tooth("S2 search position + forward doubling check is never a candidate",
      len(d09) > 0 and len(e06) > 0
      and all(f["classification"] != CANDIDATE for f in d09 + e06),
      "js=%s cpp=%s" % ([f["classification"] for f in d09],
                        [f["classification"] for f in e06]))

# ------------------------------------------------------------------- S3
d06 = unit(js, "d06-")
searchy = [f for f in d06 if f["site_kind"] == "CHARACTER_SCANNER"]
tooth("S3 a search position with an unresolved delimiter reaches no verdict",
      len(searchy) > 0
      and all(f["classification"] == ABSTAINED
              and f["abstention_reason"] == UNRESOLVED_DELIMITER_IDENTITY
              for f in d06),
      ", ".join("%s/%s" % (f["char_access_kind"], f["classification"]) for f in d06))

# ------------------------------------------------------------------- S4
search_sites = [f for f in js + cpp if f.get("char_access_kind") == "SEARCH_POSITION"]
tooth("S4 search-established sites are recorded and carry a resolution",
      len(search_sites) > 0
      and all(f.get("delimiter_resolution") in ("LITERAL", "RESOLVED", "UNRESOLVED")
              for f in search_sites),
      "%d search site(s)" % len(search_sites))

# ------------------------------------------------------------------- S5
PRIOR = json.loads((HERE / "fixtures_delim" / "PRE_R06_VERDICTS.json").read_text())
prior_ok, prior_detail = True, []
for path, expected in PRIOR["baselines"].items():
    lang = "C_CPP" if "cpp" in path else "JAVASCRIPT"
    seen = {(r["file"], r["line"], r["site_kind"]) for r in expected}
    got = sorted(({"file": f["file"], "line": f["line"], "site_kind": f["site_kind"],
                   "classification": f["classification"],
                   "boundary_rule": f.get("boundary_rule")}
                  for f in derive(HERE / path, lang)["findings"]
                  # R06's own new fixtures are not in the baseline; they are
                  # checked by S1..S4 rather than by this regression control.
                  if (f["file"], f["line"], f["site_kind"]) in seen),
                 key=lambda r: (r["file"], r["line"], r["site_kind"]))
    moved = [(a, b) for a, b in zip(expected, got) if a != b]
    if got != expected:
        prior_ok = False
        prior_detail.append("%s: %r vs %r" % (path, moved[0][0] if moved else len(got),
                                              moved[0][1] if moved else len(expected)))
    else:
        prior_detail.append("%s: %d unchanged" % (path, len(got)))
tooth("S5 every pre-R06 per-site verdict is unchanged", prior_ok,
      "; ".join(prior_detail))

# ------------------------------------------------------------------- S6
BANNED = ("vulnerab", "exploit", "severity", "attacker", "impact",
          "critical", "cve", "payload")
bad = []
for f in js + cpp:
    blob = json.dumps(f).lower()
    if f.get("reportable") is not False:
        bad.append("%s: reportable is not false" % f["file"])
    for w in BANNED:
        if w in blob:
            bad.append("%s: %r" % (f["file"], w))
tooth("S6 reportable=false and no impact or severity language", not bad,
      "; ".join(bad[:4]))

width = max(len(n) for n, _, _ in results)
for name, ok, detail in results:
    print("%-*s  %s" % (width, name, "PASS" if ok else "FAIL"))
    if not ok and detail:
        print("%s  %s" % (" " * width, detail))
passed = sum(1 for _, ok, _ in results if ok)
print("\nESCAPE_PARITY_SEARCH_POSITION=%d/%d" % (passed, len(results)))
print("PROMOTION_GATE=%s" % ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
