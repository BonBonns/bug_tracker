#!/usr/bin/env python3
"""Denylist / pattern matcher-kind mismatch verdict — the JS/TS analogue of the
Forminator forminator_allowed_mime_types() + wp_check_filetype() bypass.

PATTERN
-------
A security DENYLIST removes dangerous tokens by EXACT match (includes/has/===),
but the surviving tokens are later used as PATTERNS (regex alternation). A token
pattern-equivalent to a forbidden one but not string-equal (`ph(p)` vs `php`,
`php|phtml`) survives the exact check yet still matches as a pattern downstream.

CORE DISCRIMINATOR (fully static, no taint needed)
  guard match-kind vs consumer match-kind:
    EXACT denylist guard  +  PATTERN consumer with UNESCAPED token  =  BYPASS.
  Any of these breaks it (all present as negative controls in the fixture):
    * denylist NORMALIZES the key before matching (strips metachars)  -> safe
    * consumer matches EXACTLY too (no regex)                          -> safe
    * consumer ESCAPES the token before building the regex            -> safe

VERDICTS (CANDIDATE, never "VULNERABLE")
  CANDIDATE_DENYLIST_PATTERN_BYPASS  an EXACT denylist filter whose result flows
     into a PATTERN consumer that interpolates the token UNESCAPED.
  SAFE_NORMALIZED_DENYLIST           the denylist normalizes keys before match.
  SAFE_ESCAPED_CONSUMER              the consumer escapes the token.
  SAFE_EXACT_CONSUMER                the consumer also matches exactly.

CEILINGS
  * filter->consumer linkage is intra-method structural (nested call or same
    method), matched by callee name; a link through a field or across modules is
    under-approximated (missed, never false-alarmed).
  * "escaped" is satisfied by any escaper/metachar-replace inside the regex
    expression; an escaper that is buggy or partial is treated as safe (the
    detector checks presence, not correctness of the escape).
"""
import json, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required denylist fact file missing: {p}")
    out, seen = [], set()
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            xs = ln.split("\t")
            k = tuple(xs)
            if k not in seen:
                seen.add(k); out.append(xs)
    return out


def _short(fullname):
    tail = fullname.split("::program", 1)[-1]
    return tail[1:] if tail.startswith(":") else tail


def derive(raw):
    raw = Path(raw)
    guards = _rows(raw / "denylist_guards.tsv", 6)
    consumers = _rows(raw / "pattern_consumers.tsv", 5)
    flows = _rows(raw / "collection_flow.tsv", 5)

    # Per file: does any EXACT / NORMALIZED denylist guard exist, keyed by method.
    guard_by_method = {}    # (file, short_method) -> "EXACT"|"NORMALIZED"
    for f_, meth, line, kind, code, norm in guards:
        key = (f_, _short(meth))
        # EXACT is the dangerous kind; if both seen, EXACT dominates the finding
        prev = guard_by_method.get(key)
        if prev != "EXACT":
            guard_by_method[key] = kind

    # Per file: does a method contain an UNESCAPED / ESCAPED pattern consumer?
    # Ignore the program-scope duplicate rows (empty short name).
    consumer_by_method = {}  # (file, short_method) -> {"escaped": bool} (unescaped wins)
    for f_, meth, line, code, escaped in consumers:
        sm = _short(meth)
        if not sm:
            continue
        key = (f_, sm)
        esc = escaped == "true"
        if key not in consumer_by_method:
            consumer_by_method[key] = esc
        else:
            # an unescaped consumer anywhere in the method is the dangerous one
            consumer_by_method[key] = consumer_by_method[key] and esc

    findings = []
    seen = set()
    for f_, caller, filt, cons, mode in flows:
        gkind = guard_by_method.get((f_, filt))
        if gkind is None:
            continue                       # `filt` isn't a denylist filter
        # find the consumer method's pattern status in the same file
        cesc = consumer_by_method.get((f_, cons))
        key = (f_, filt, cons)
        if key in seen:
            continue
        seen.add(key)

        if gkind == "NORMALIZED":
            verdict = "SAFE_NORMALIZED_DENYLIST"
        elif cesc is None:
            verdict = "SAFE_EXACT_CONSUMER"     # consumer builds no regex
        elif cesc is True:
            verdict = "SAFE_ESCAPED_CONSUMER"
        else:
            verdict = "CANDIDATE_DENYLIST_PATTERN_BYPASS"

        findings.append({"file": f_, "filter": filt, "consumer": cons,
                         "guard_match_kind": gkind,
                         "consumer_is_regex": cesc is not None,
                         "consumer_escaped": cesc,
                         "link": mode, "verdict": verdict})

    return {
        "schema": "denylist-pattern-bypass-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags an EXACT-match security "
                 "denylist whose surviving tokens flow into an UNESCAPED regex/"
                 "pattern consumer -- the JS/TS shape of the Forminator "
                 "forminator_allowed_mime_types()/wp_check_filetype() bypass, "
                 "where `ph(p)` survives an exact `php` blocklist but still "
                 "matches as a pattern."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "deny-out/raw"), indent=2))
