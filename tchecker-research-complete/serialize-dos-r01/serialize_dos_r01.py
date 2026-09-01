#!/usr/bin/env python3
"""SERIALIZE-DOS-R01 -- canonical, property-local reconciliation revision.

Standalone. Not wired into any shared pipeline module (provenance, reachability,
staged enablement, or the production aggregator). `reportable` is fixed to `false`
on every finding produced here -- pipeline integration is explicitly deferred to a
separate, later task. This module must not be imported by, and does not import,
anything under semantic-bucket-pilot/scanner-v2's shared pipeline files, the ReDoS
property files, or the N-API status files.

WHY TWO CLASSIFICATION AXES, NEVER MERGED
------------------------------------------
This repository already has two independent, real, working implementations sharing
a "serialize-dos"/CWE-674 label:

  1. `gates/serialize_dos_verdict.py` (+ `gates/gate_serialize_dos.py`) -- a direct,
     fact-based, 100%-deterministic verdict over `export_serialize_facts.sc`'s three
     fact tables. Models ONE mechanism: a synchronous, uncaught `RangeError` from
     serializing deeply-nested attacker JSON kills the whole Node process. Its "guard"
     vocabulary is entirely about crash-safety nets (try/catch, a depth/size guard, a
     process-level uncaughtException handler).
  2. `tchecker-property-adjudicator`'s generic taint/property-propagation engine
     (`adjudicate_js.py` + `property_configs/serialize_dos.json` +
     `setup_candidate.sc`/`export_property_propagation.sc`/`export_trace_identity.sc`)
     -- a genuinely interprocedural, config-seamed engine modeling a DIFFERENT
     mechanism: whether attacker-controlled data reaches a serialization sink with its
     size/structure left unbounded by any on-path transform -- a resource-cost
     question (CPU/memory/event-loop-blocking) independent of whether any call
     actually throws. It has ZERO modeling anywhere of try/catch or uncaughtException
     (confirmed by exhaustive grep of the whole pipeline; see RECONCILIATION.md).

RECONCILIATION.md (this directory) documents the full, executed, exact comparison
across every required axis and the concrete case where the two disagree (a value
serialized inside try/catch, through a transform whose bounding effect is unknown: the
direct implementation says SAFE_TRY_CATCH; the taint engine says CANDIDATE_OPEN --
both correct, answering different questions). Per that finding, this revision computes
TWO INDEPENDENT classification axes per candidate finding and never merges them into
one flat verdict:

  crash_dos_classification            -- reuses the direct implementation's proven,
                                          frozen guard model verbatim (same six-way
                                          vocabulary, same semantics). See
                                          `_crash_dos_classification()`.
  size_structure_dos_classification   -- a NEW, deterministic-only, intentionally
                                          narrow structural approximation of the
                                          taint-engine's question. See
                                          `_size_structure_dos_classification()` for
                                          the explicit, disclosed scope reduction this
                                          represents (single-hop, intraprocedural,
                                          never a reimplementation of the taint
                                          engine's interprocedural transform-chain /
                                          trace-identity / semantic-review machinery).

Both axes are CANDIDATE-only vocabularies (never "VULNERABLE"); this module makes no
exploitability or impact claim of any kind, on either axis, ever -- only a
serialization-handling classification (crash axis) and a resource-bound classification
(size axis).

REQUIRED FACT SCHEMA (property-local; NOT the shared corpus pipeline's fact tables)
------------------------------------------------------------------------------------
  serialize_sinks.tsv (8 col)     -- from the EXISTING, frozen, read-only-consumed
  uncaught_handlers.tsv (2 col)      `export_serialize_facts.sc` (owned by
  depth_guards.tsv (2 col)           tchecker-property-adjudicator/producers/, used
                                      here exactly as `gates/serialize_dos_verdict.py`
                                      already uses it -- never modified).
  transform_presence.tsv (6 col)  -- from the NEW, property-local
                                      `producers/transform_presence.sc` in this
                                      directory: file, method, line, arg_code,
                                      transform_present, transform_callee.
"""
import json, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required serialize-DoS-R01 fact file missing: {p}")
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


def _crash_dos_classification(is_attacker, bounded, in_trycatch, depth_guarded, has_net):
    """Verbatim reuse of gates/serialize_dos_verdict.py's guard-precedence logic and
    vocabulary (the CRASH_DOS subproperty: a synchronous, uncaught RangeError kills the
    process). See RECONCILIATION.md Sec.2 row "Guard/bound requirements modeled"."""
    if not is_attacker:
        return "SAFE_NOT_ATTACKER_CONTROLLED"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if in_trycatch:
        return "SAFE_TRY_CATCH"
    if depth_guarded:
        return "SAFE_DEPTH_GUARDED"
    if has_net:
        return "SUSPICIOUS_UNGUARDED_SERIALIZE"
    return "CANDIDATE_UNGUARDED_SERIALIZE_DOS"


def _size_structure_dos_classification(is_attacker, bounded, transform_present, transform_fact_present):
    """NEW, deterministic-only, intentionally narrow approximation of the
    tchecker-property-adjudicator taint engine's ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE
    question (the SIZE_STRUCTURE_DOS subproperty).

    Explicit, disclosed scope reduction vs. that engine (never claimed to be a
    replacement -- see RECONCILIATION.md Sec.4):
      - single-hop only: does not follow a transform into its own body, does not
        resolve interprocedural transform chains, does not build the taint engine's
        trace-identity / property-propagation lattice.
      - never resolves whether a transform actually bounds size: any detected
        transform on the flow ABSTAINS (ABSTAIN_TRANSFORM_PRESENT) rather than
        guessing, and never accepts a semantic/LLM hint to resolve it (this module has
        no such mechanism at all, by design -- reportable stays false regardless).
      - a missing transform_presence.tsv row for an otherwise-real sink is itself an
        abstention (ABSTAIN_MISSING_TRANSFORM_FACT), not a silent default, per this
        session's abstain-first discipline.

    A bounded_literal precondition (the SAME structural fact export_serialize_facts.sc
    already computes) is reused for BOTH axes without conflating them: a freshly-built
    literal of scalars cannot carry deeply-nested attacker JSON regardless of whether
    the concern is a crash or a resource cost -- it is a shared precondition of the
    underlying data shape, not a guard specific to either subproperty.
    """
    if not is_attacker:
        return "SAFE_NOT_ATTACKER_CONTROLLED"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if not transform_fact_present:
        return "ABSTAIN_MISSING_TRANSFORM_FACT"
    if transform_present:
        return "ABSTAIN_TRANSFORM_PRESENT"
    return "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE"


def derive(raw):
    raw = Path(raw)
    sinks = _rows(raw / "serialize_sinks.tsv", 8)
    handlers = _rows(raw / "uncaught_handlers.tsv", 2)
    guards = _rows(raw / "depth_guards.tsv", 2)
    transforms = _rows(raw / "transform_presence.tsv", 6)

    uncaught_pkgs = {_pkg(h[0]) for h in handlers if h[1] == "uncaughtException"}
    guarded_methods = {(g[0], g[1]) for g in guards}
    # keyed by (file, method, line) -- matches sinks 1:1 by construction (both
    # producers scan the SAME real serializer call sites; see transform_presence.sc's
    # own docstring)
    transform_by_site = {(t[0], t[1], t[2]): (t[4] == "true", t[5]) for t in transforms}

    findings = []
    for f_, meth, line, callee, arg, attacker, in_try, bounded_lit in sinks:
        pkg = _pkg(f_)
        is_attacker = attacker == "true"
        in_trycatch = in_try == "true"
        bounded = bounded_lit == "true"
        depth_guarded = (f_, meth) in guarded_methods
        has_net = pkg in uncaught_pkgs

        site = (f_, meth, line)
        transform_fact_present = site in transform_by_site
        transform_present, transform_callee = transform_by_site.get(site, (False, ""))

        crash_cls = _crash_dos_classification(is_attacker, bounded, in_trycatch, depth_guarded, has_net)
        size_cls = _size_structure_dos_classification(is_attacker, bounded, transform_present, transform_fact_present)

        findings.append({
            "file": f_, "package": pkg, "method": meth, "line": line,
            "callee": callee, "arg": arg,
            "attacker_controlled": is_attacker,
            "in_try_catch": in_trycatch,
            "bounded_literal": bounded,
            "depth_guarded": depth_guarded,
            "uncaught_handler_present": has_net,
            "transform_present": transform_present,
            "transform_callee": transform_callee,
            "transform_fact_present": transform_fact_present,
            "crash_dos_classification": crash_cls,
            "size_structure_dos_classification": size_cls,
            "reportable": False,
        })

    return {
        "schema": "serialize-dos-r01/0.1",
        "note": ("Two independent CANDIDATE-only classification axes per finding, "
                 "never merged: crash_dos_classification (process-crash-via-uncaught-"
                 "RangeError model, reusing gates/serialize_dos_verdict.py's guard "
                 "logic verbatim) and size_structure_dos_classification (a new, "
                 "deterministic-only, intentionally narrow structural approximation "
                 "of the tchecker-property-adjudicator taint engine's serialized-"
                 "size/structure question -- see RECONCILIATION.md). reportable is "
                 "fixed to false on every finding: pipeline integration is "
                 "explicitly deferred. No exploitability, severity, or impact claim "
                 "is made on either axis."),
        "classification": "SERIALIZE_DOS_CANDIDATE_SET",
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "fixtures/raw"), indent=2))
