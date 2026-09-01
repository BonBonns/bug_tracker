#!/usr/bin/env python3
"""Build the escape-run parity test matrix (runs 0..6) shared by both engine harnesses.

For a quoted value followed by a run of N escape characters and then a quote:
    N even -> that quote TERMINATES the value; a following second value is recoverable
    N odd  -> that quote is ESCAPED; the value runs on to the next unescaped quote

Subject:   Q abc \\*N Q , _ Q next Q
Expected:  N even -> ["abc" + "\\"*N, "next"]
           N odd  -> ["abc" + "\\"*N + Q + ", "]
"""
import json
import sys

MAX_RUN = 6


def subject(q, n):
    return q + "abc" + ("\\" * n) + q + ", " + q + "next" + q


def expected(q, n):
    if n % 2 == 0:
        return ["abc" + ("\\" * n), "next"]
    return ["abc" + ("\\" * n) + q + ", "]


def build(rules):
    """rules: list of {id, dialect, pattern, quote}"""
    cases = []
    for r in rules:
        q = r["quote"]
        for n in range(MAX_RUN + 1):
            cases.append({"rule_id": r["id"], "dialect": r["dialect"],
                          "pattern": r["pattern"], "run_length": n,
                          "parity": "even" if n % 2 == 0 else "odd",
                          "subject": subject(q, n), "expected": expected(q, n)})
    return cases


if __name__ == "__main__":
    json.dump(build(json.load(open(sys.argv[1]))), sys.stdout, indent=1)
