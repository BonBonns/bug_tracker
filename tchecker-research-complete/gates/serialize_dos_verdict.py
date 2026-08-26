#!/usr/bin/env python3
"""Unguarded serialize-on-attacker-data DoS verdict — the JS/TS shape of the
Unleash CWE-674 crash (GHSA-r5pq-6chh-j3xp).

PATTERN
-------
An error/format path calls JSON.stringify (or util.inspect) on a raw
request-body value with no guard. Deeply-nested JSON makes it throw RangeError
synchronously; the throw is not wrapped in try/catch and the process registers
no uncaughtException handler, so Node exits(1) -- an unauthenticated
single-request DoS.

LEGS
  L1 SERIALIZE SINK   JSON.stringify / util.inspect on ...
  L2 ATTACKER DATA    ... a value read from the request body.
  L3 UNGUARDED        the call is not inside try/catch AND no depth/size guard
                      precedes it.
  L4 NO SAFETY NET    the process registers no uncaughtException handler, so a
                      synchronous throw crashes the whole process.

VERDICTS (CANDIDATE, never "VULNERABLE")
  CANDIDATE_UNGUARDED_SERIALIZE_DOS   L1+L2+L3+L4 -- a process-killing sink.
  SUSPICIOUS_UNGUARDED_SERIALIZE      L1+L2+L3 but an uncaughtException handler
     exists: the throw is caught process-wide, so it degrades to a handled error
     rather than a hard crash (still an anti-pattern; lower severity).
  SAFE_TRY_CATCH                      the serialize call is inside try/catch.
  SAFE_DEPTH_GUARDED                  a depth/size guard precedes the serialize.
  SAFE_NOT_ATTACKER_CONTROLLED        the serialized value is not request data.

CEILINGS
  * attacker-control is a lexical taint (req.body / lodash.get(body) / a local
    assigned from them); a body value laundered through a helper return is
    under-approximated.
  * the uncaughtException net is a PACKAGE-level fact; in a real monorepo the
    handler may live in a separate entrypoint not scanned together -- treat a
    SUSPICIOUS as "confirm the process entrypoint" rather than "safe".
  * try/catch is lexical; a serialize in a callback that escapes the try (async)
    is not actually guarded -- flagged conservatively as guarded here (a known
    false-negative direction, noted for the async-boundary follow-up).
"""
import json, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required serialize-DoS fact file missing: {p}")
    out, seen = [], set()
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            xs = ln.split("\t")
            if tuple(xs) not in seen:
                seen.add(tuple(xs)); out.append(xs)
    return out


def _pkg(path):
    parts = Path(path).parts
    return parts[0] if parts else path


def derive(raw):
    raw = Path(raw)
    sinks = _rows(raw / "serialize_sinks.tsv", 8)
    handlers = _rows(raw / "uncaught_handlers.tsv", 2)
    guards = _rows(raw / "depth_guards.tsv", 2)

    # package-level: uncaughtException handler present?
    uncaught_pkgs = {_pkg(h[0]) for h in handlers if h[1] == "uncaughtException"}
    # method-level: depth guard present?
    guarded_methods = {(g[0], g[1]) for g in guards}

    findings = []
    for f_, meth, line, callee, arg, attacker, in_try, bounded_lit in sinks:
        pkg = _pkg(f_)
        is_attacker = attacker == "true"
        in_trycatch = in_try == "true"
        bounded = bounded_lit == "true"
        depth_guarded = (f_, meth) in guarded_methods
        has_net = pkg in uncaught_pkgs

        if not is_attacker:
            verdict = "SAFE_NOT_ATTACKER_CONTROLLED"
        elif bounded:
            # taint reaches it, but the value is a bounded literal of scalars —
            # cannot carry deeply-nested attacker JSON, so not the DoS shape.
            verdict = "SAFE_BOUNDED_LITERAL"
        elif in_trycatch:
            verdict = "SAFE_TRY_CATCH"
        elif depth_guarded:
            verdict = "SAFE_DEPTH_GUARDED"
        elif has_net:
            verdict = "SUSPICIOUS_UNGUARDED_SERIALIZE"
        else:
            verdict = "CANDIDATE_UNGUARDED_SERIALIZE_DOS"

        findings.append({"file": f_, "package": pkg, "method": meth, "line": line,
                         "callee": callee, "arg": arg,
                         "attacker_controlled": is_attacker,
                         "in_try_catch": in_trycatch,
                         "bounded_literal": bounded,
                         "depth_guarded": depth_guarded,
                         "uncaught_handler_present": has_net,
                         "verdict": verdict})

    return {
        "schema": "unguarded-serialize-dos-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags JSON.stringify/util.inspect "
                 "on request-body data with no try/catch and no depth guard, in a "
                 "process with no uncaughtException handler -- the JS/TS shape of "
                 "the Unleash single-request OpenAPI-validation-error DoS "
                 "(CWE-674). A try/catch, a depth guard, non-attacker data, or a "
                 "process-level uncaughtException net each de-escalates."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "ser-out/raw"), indent=2))
