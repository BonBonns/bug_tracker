#!/usr/bin/env python3
"""ADJUDICATE-ITERATIVE-R01: drives adjudicate_js.py (frozen, unmodified -- see
tchecker-property-adjudicator/adjudicator/adjudicate_js.py) through as many rounds as it
takes to actually account for EVERY unresolved source-to-sink alternative at one sink, not
just the first one a single invocation happens to stop at.

Why this exists: adjudicate_js.py's own main() loop is a one-question-per-round, interactive
protocol -- it asks about exactly one unresolved property, and only continues to the NEXT one
if TCH_HINTS already contains a real answer for the property it just asked about. Every
existing call site (redos_verdict.py, path_traversal_verdict.py, and this session's own
Serialize DoS pipeline wiring) invokes it EXACTLY ONCE per sink with TCH_HINTS=no_hints.json
(a real, deliberately empty {}) -- correct discipline for "never fabricate an answer", but as
a side effect this means a sink fed by MORE THAN ONE distinct unresolved alternative only ever
gets its FIRST alternative asked about; any others sit in evidence_final.json's own
semantically_unresolved__SEMANTICALLY_UNRESOLVED list forever, never packaged into their own
llm_input_N.json, and nothing anywhere discloses that they were never even asked about (as
opposed to genuinely reviewed and ruled out). Confirmed real via a constructed two-alternative
fixture (two distinct opaque transforms converging on one sink): the single-invocation call
produces exactly one llm_input_1.json while evidence_final.json's own unresolved list carries
three still-unaddressed properties.

This module closes that gap with a real, resumable loop:
  - Maintains an accumulating {property_id: {proposed_value, confidence, rationale}} hints
    dict across rounds, written to TCH_HINTS before each invocation.
  - Since adjudicate_js.py's own __main__ always rebuilds evidence_v0 from scratch and replays
    every round whose target already has a hint before reaching the next unanswered one, an
    invocation with K accumulated hints naturally reaches round K+1 -- exactly the next
    question -- and stops there if K+1's target has no hint yet.
  - `ask_fn(question_dict, round_no) -> {"proposed_value", "confidence", "rationale"} | None`
    is the pluggable live answerer. Returning None (or passing ask_fn=None, the default,
    matching every existing call site's current behavior byte-for-byte) means "no live answer
    right now" -- the driver stops honestly at whatever round it reached, exactly like every
    existing call site did before this module existed, but UNLIKE those call sites it also
    computes and returns `unaddressed_alternative_count`: the real count of properties in
    evidence_final.json's own semantically_unresolved list that were never packaged into an
    llm_input file at all (semantic_hint is still None) -- so a caller with no live answerer
    wired in still gets an honest disclosure of what was left out, instead of silence.
  - A real answer IS accepted into the security-property lattice only under
    adjudicate_js.py's own frozen hint_acceptance_rule (HIGH confidence and a resolved
    subject_transform) -- this module never second-guesses or bypasses that; a LOW/MEDIUM or
    UNKNOWN answer is still folded (so the loop correctly advances to the NEXT alternative
    rather than re-asking the same one forever) but correctly never resolves the property on
    its own, exactly as adjudicate_js.py's own frozen lattice already guarantees.
  - Bounded by max_rounds (default 12, generous -- every real fixture and package seen this
    session needed at most 3) as a defensive abstain, never a silent infinite loop.

Never touches adjudicate_js.py's own on-disk evidence_final.json: the extra
`_adjudication_loop` bookkeeping key is added only to the in-memory dict this module returns
to its caller, so any frozen downstream reducer that re-reads evidence_final.json directly off
disk (e.g. serialize_dos_r03.py's own derive()) sees exactly what adjudicate_js.py itself wrote,
byte for byte -- this module only ever adds information for ITS OWN callers, never rewrites
the frozen tool's own real output.
"""
import json
import os
import subprocess
import sys


def _llm_input_rounds(out_dir):
    if not os.path.isdir(out_dir):
        return []
    out = []
    for fn in os.listdir(out_dir):
        if fn.startswith("llm_input_") and fn.endswith(".json"):
            try:
                out.append(int(fn[len("llm_input_"):-len(".json")]))
            except ValueError:
                continue
    return sorted(out)


def _unaddressed_count(evidence):
    unresolved = evidence.get("semantically_unresolved__SEMANTICALLY_UNRESOLVED", [])
    return sum(1 for p in unresolved if p.get("semantic_hint") is None)


def run_adjudicate_sink_iterative(adjudicator_dir, raw_dir, src_dir, out_dir, property_config,
                                    sink=None, sink_kind=None, finding_file=None,
                                    hints=None, ask_fn=None, max_rounds=12, timeout=120):
    """Returns (evidence_final_dict_or_None, err_or_None). On success, evidence carries an
    extra `_adjudication_loop` key: {rounds_asked, rounds_answered, unaddressed_alternative_count}.
    `hints`, if supplied, is mutated in place with every accepted-or-not answer this call
    obtained (so a caller reusing it across sinks/rounds sees the accumulated state)."""
    hints = hints if hints is not None else {}
    os.makedirs(out_dir, exist_ok=True)
    # NOT inside out_dir: adjudicate_js.py's own __main__ deletes every *.json file already
    # in TCH_OUT (`for f in OUT.glob("*.json"): f.unlink()`) BEFORE it ever reads TCH_HINTS --
    # a hints file living inside out_dir would be wiped by the very invocation meant to read
    # it. Confirmed real via a first attempt that did exactly this and hit a real
    # FileNotFoundError. Kept as a sibling path instead.
    hints_path = out_dir.rstrip("/") + ".accumulated_hints.json"

    rounds_asked = 0
    while True:
        with open(hints_path, "w") as f:
            json.dump(hints, f)
        env = dict(os.environ)
        env.update({
            "TCH_RAW": raw_dir, "TCH_SRC": src_dir, "TCH_OUT": out_dir,
            "TCH_PROPERTY_CONFIG": property_config, "TCH_HINTS": hints_path,
        })
        if sink:
            env["TCH_SINK"] = sink
        if sink_kind:
            env["TCH_SINK_KIND"] = sink_kind
        if finding_file:
            env["TCH_FINDING"] = finding_file
        try:
            r = subprocess.run([sys.executable, "adjudicate_js.py"], cwd=adjudicator_dir, env=env,
                                capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            return None, f"adjudicate_js.py timed out after {timeout}s: {e}"

        evidence_path = os.path.join(out_dir, "evidence_final.json")
        if not os.path.isfile(evidence_path):
            return None, r.stdout + r.stderr
        with open(evidence_path) as f:
            evidence = json.load(f)

        rounds_now = _llm_input_rounds(out_dir)
        new_round = max(rounds_now) if rounds_now else 0
        if new_round <= len(hints):
            # Nothing beyond what we've already answered -- fully resolved (target is None)
            # or genuinely exhausted with fewer live questions than hints we happened to hold.
            evidence["_adjudication_loop"] = {
                "rounds_asked": rounds_asked, "rounds_answered": len(hints),
                "unaddressed_alternative_count": _unaddressed_count(evidence),
            }
            return evidence, None

        rounds_asked = new_round

        if ask_fn is None or rounds_asked > max_rounds:
            evidence["_adjudication_loop"] = {
                "rounds_asked": rounds_asked, "rounds_answered": len(hints),
                "unaddressed_alternative_count": _unaddressed_count(evidence),
            }
            if rounds_asked > max_rounds:
                evidence["_adjudication_loop"]["abstain_reason"] = "LOOP_LIMIT_EXCEEDED"
            return evidence, None

        llm_input_path = os.path.join(out_dir, f"llm_input_{new_round}.json")
        with open(llm_input_path) as f:
            question = json.load(f)
        answer = ask_fn(question, new_round)
        if answer is None:
            evidence["_adjudication_loop"] = {
                "rounds_asked": rounds_asked, "rounds_answered": len(hints),
                "unaddressed_alternative_count": _unaddressed_count(evidence),
            }
            return evidence, None

        hints[question["property_id"]] = {
            "proposed_value": answer["proposed_value"],
            "confidence": answer["confidence"],
            "rationale": answer["rationale"],
        }
        # loop again: re-invoke with the newly-augmented hints, which replays every prior
        # round transparently and reaches the next unanswered question (if any).
