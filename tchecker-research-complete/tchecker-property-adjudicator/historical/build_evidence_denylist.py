#!/usr/bin/env python3
"""Denylist-bypass -> CanonicalEvidenceSet (predicate / domain-coverage semantics).

Fourth semantic shape. The security property is NOT matcher_kind(check) !=
matcher_kind(consumer). It is set/domain containment:

    prohibited_consumer_domain  subseteq  rejected_check_domain ?

  established contained  -> SAFE
  disproven             -> CANDIDATE
  cannot be established  -> SEMANTICALLY_OPEN

Matcher kinds and regex breadth are only EVIDENCE feeding that judgement. Value-flow
fields are NOT_APPLICABLE (no attacker value path is required to characterise the
predicate mismatch; provenance is populated only if genuinely established).
"""
import collections, sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "dp-out/raw")
NA = {"status": "NOT_APPLICABLE", "reason": "denylist-bypass is a predicate/domain-coverage question; "
      "an attacker value path is not required to characterise the mechanism"}


def rows(name, n):
    p = RAW / name
    seen, out = set(), []
    for ln in (p.read_text().splitlines() if p.exists() else []):
        f = ln.split("\t")
        if len(f) == n and ln not in seen and "function " not in ln and "=>" not in ln:
            seen.add(ln); out.append(f)
    return out


facts = collections.defaultdict(lambda: {"checks": [], "consumers": []})
for r in rows("matcher_facts.tsv", 11):
    file_, method, role, node, line, kind, value, pattern, breadth, esc, norm_from = r
    rec = {"node": node, "line": line, "kind": kind, "value": value.strip(),
           "pattern": pattern, "breadth": breadth, "esc": esc, "norm_from": norm_from.strip()}
    key = (file_.split("/")[-1], method.split(":")[-1])
    if role == "CHECK":
        facts[key]["checks"].append(rec)
    else:
        facts[key]["consumers"].append(rec)


def same_value(chk, con):
    # same value identity, OR the consumer value is a normalization of the check value
    if chk["value"] == con["value"]:
        return "SAME", None
    if con["norm_from"] and con["norm_from"] == chk["value"]:
        return "NORMALIZED", con["norm_from"]
    return "DIFFERENT", None


def containment(chk, con, rel):
    """prohibited_consumer_domain ⊆ rejected_check_domain ?  Returns (status, reason)."""
    if rel == "DIFFERENT":
        return "NOT_JOINED", "check and consumer operate on different values"
    if con["esc"] in ("INLINE", "PRIOR_LOCAL"):
        return "ESTABLISHED_CONTAINED", "consumer matches the escaped literal token (⊆ rejected set)"
    if con["kind"] == "EXACT_KEY":
        return "ESTABLISHED_CONTAINED", "consumer matches exactly, same representation as the check"
    if rel == "NORMALIZED":
        return "UNKNOWN", "value is normalized between check and consumer; comparison domain changed"
    if con["kind"] == "REGEX":
        if con["breadth"] == "ANCHORED_FINITE" and chk["kind"] == "REGEX" and chk["breadth"] == "ANCHORED_FINITE":
            return "ESTABLISHED_CONTAINED", "consumer's finite anchored language ⊆ check's rejected language"
        if con["breadth"] == "BROAD" and chk["kind"] == "EXACT_KEY":
            return "DISPROVEN", "consumer regex matches representations outside the finite exact rejected set"
        if con["breadth"] == "UNKNOWN":
            return "UNKNOWN", "consumer matcher built via helper/dynamic; its accepted domain is unresolved"
    return "UNKNOWN", "containment could not be established from available facts"


def build(method):
    d = facts[method]
    alternatives = []
    for con in d["consumers"]:
        best = None
        for chk in d["checks"]:
            rel, nsrc = same_value(chk, con)
            cont, reason = containment(chk, con, rel)
            cand = {"check": chk, "consumer": con, "relation": rel, "containment": cont, "reason": reason}
            # prefer a joined check over a non-joined one
            if best is None or (best["relation"] == "DIFFERENT" and rel != "DIFFERENT"):
                best = cand
        if best is None:
            continue
        cont = best["containment"]
        if cont == "NOT_JOINED":
            verdict, coverage, q = "NOT_A_FINDING", "SEMANTICALLY_CLOSED", None
        elif cont == "ESTABLISHED_CONTAINED":
            verdict, coverage, q = "SAFE_DOMAIN_CONTAINED", "SEMANTICALLY_CLOSED", None
        elif cont == "DISPROVEN":
            verdict, coverage, q = "CANDIDATE_DENYLIST_BYPASS", "SEMANTICALLY_CLOSED", None
        else:
            verdict, coverage = "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"
            q = ("Does the rejection predicate exclude every representation the consumer interprets as "
                 "prohibited, or can a representation pass the check while still matching the consumer's "
                 "broader interpretation? (%s)" % best["reason"])
        alternatives.append({**best, "verdict": verdict, "coverage": coverage, "question": q})
    # method verdict: per-alternative — a safe/contained alternative never closes a
    # disproven or open one.
    verds = [a["verdict"] for a in alternatives]
    if "CANDIDATE_DENYLIST_BYPASS" in verds:
        mv, mc = "CANDIDATE_DENYLIST_BYPASS", "SEMANTICALLY_CLOSED"
    elif "NEEDS_SEMANTIC_REVIEW" in verds:
        mv, mc = "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"
    elif any(v == "SAFE_DOMAIN_CONTAINED" for v in verds):
        mv, mc = "SAFE_DOMAIN_CONTAINED", "SEMANTICALLY_CLOSED"
    else:
        mv, mc = "NOT_A_FINDING", "SEMANTICALLY_CLOSED"
    return {"method": method, "alternatives": alternatives, "verdict": mv, "coverage": mc}


if __name__ == "__main__":
    for method in sorted(facts):
        if method[1] in ("program", "esc", "norm", "makeMatcher"):
            continue
        ev = build(method)
        if not ev["alternatives"]:
            continue
        print(f"[{method[0]}::{method[1]}] verdict={ev['verdict']}  coverage={ev['coverage']}")
        for a in ev["alternatives"]:
            print(f"     check={a['check']['kind']}/{a['check'].get('breadth','')} "
                  f"consumer={a['consumer']['kind']}/{a['consumer']['breadth']} "
                  f"rel={a['relation']} containment={a['containment']} -> {a['verdict']}  "
                  f"[value-flow: {NA['status']}]")
            if a["question"]:
                print(f"        Q: {a['question']}")
