#!/usr/bin/env python3
"""Permanent regression test for the abstention-collapse false negative.
See docs/ABSTENTION_COLLAPSE.md. Run with no arguments; exits non-zero on failure.
Imports adjudicate_js directly (no fixtures/CPG needed) to test adjudicate() in isolation,
proving the disposition layer enforces the invariant independently of the acceptance guard."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "adjudicator"))
import adjudicate_js as adj

FAIL = []

def check(name, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}")
    if not ok:
        FAIL.append(name)

def prop(deterministic_status, adjudication_use, proposed_value=None, confidence="HIGH"):
    p = {"deterministic_status": deterministic_status, "adjudication_use": adjudication_use}
    if proposed_value is not None:
        p["semantic_hint"] = {"proposed_value": proposed_value, "confidence": confidence}
    else:
        p["semantic_hint"] = None
    return p

print("=== permanent regression matrix (docs/ABSTENTION_COLLAPSE.md) ===")

# Row 1: identity established, HIGH, SAFE -> resolved safe
ev = {"value_preservation": "OPEN",
      "semantically_unresolved__SEMANTICALLY_UNRESOLVED": [
          prop("UNKNOWN", "ACCEPTED_HINT", "SAFE")]}
_, disp = adj.adjudicate(ev)
check("established+HIGH+SAFE", disp, "RESOLVED_SAFE_BY_ACCEPTED_HINT")

# Row 2: identity established, HIGH, UNSAFE -> resolved candidate
ev = {"value_preservation": "OPEN",
      "semantically_unresolved__SEMANTICALLY_UNRESOLVED": [
          prop("UNKNOWN", "ACCEPTED_HINT", "UNSAFE")]}
_, disp = adj.adjudicate(ev)
check("established+HIGH+UNSAFE", disp, "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT")

# Row 3: identity established, HIGH, UNKNOWN -> stays OPEN (the abstention-collapse case)
ev = {"value_preservation": "OPEN",
      "semantically_unresolved__SEMANTICALLY_UNRESOLVED": [
          prop("UNKNOWN", "ACCEPTED_HINT", "UNKNOWN")]}
_, disp = adj.adjudicate(ev)
check("established+HIGH+UNKNOWN", disp, "CANDIDATE_OPEN")

# Row 4: identity unknown (never accepted), HIGH, SAFE -> stays OPEN (advisory only)
ev = {"value_preservation": "OPEN",
      "semantically_unresolved__SEMANTICALLY_UNRESOLVED": [
          prop("UNKNOWN", "NEEDS_MORE_REVIEW", "SAFE")]}
_, disp = adj.adjudicate(ev)
check("unknown+HIGH+SAFE(advisory)", disp, "CANDIDATE_OPEN")

print()
print("=== defense-in-depth: forged ACCEPTED_HINT+UNKNOWN, bypassing hint_acceptance_rule ===")
ev = {"value_preservation": "OPEN",
      "semantically_unresolved__SEMANTICALLY_UNRESOLVED": [
          prop("UNKNOWN", "ACCEPTED_HINT", "UNKNOWN")]}
_, disp = adj.adjudicate(ev)
check("forged ACCEPTED_HINT+UNKNOWN (disposition layer must self-enforce)", disp, "CANDIDATE_OPEN")

print()
print("=== hint_acceptance_rule: UNKNOWN never gets ACCEPTED_HINT, any confidence ===")
p = {"subject_transform": "TRACE:x", "semantic_hint": {"proposed_value": "UNKNOWN", "confidence": "HIGH"}}
use = adj.hint_acceptance_rule(p)
check("hint_acceptance_rule(UNKNOWN, HIGH, identity established)", use, "NEEDS_MORE_REVIEW")

if FAIL:
    print(f"\n{len(FAIL)} FAILURE(S): {FAIL}")
    sys.exit(1)
print("\nALL PASS")
