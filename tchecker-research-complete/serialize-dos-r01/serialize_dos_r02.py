#!/usr/bin/env python3
"""SERIALIZE-DOS-R02 -- architectural correction over R01: a coordinator, not a
replacement, for the two existing canonical implementations.

WHY R02 EXISTS
--------------
R01 (`serialize_dos_r01.py`) computed `size_structure_dos_classification` from its own
new, intraprocedural, single-hop `transform_presence.tsv` approximation. Manual review
of R01's frozen `motifer@26.1.1` blind result (`study/blind_motifer_review/
MOTIFER_MANUAL_REVIEW.md`) found that approximation agreed with the REAL taint engine
only by construction, not by architecture: R01 never actually consulted the taint
engine. That review also surfaced a genuine, disclosed limitation IN the taint engine's
own `setup_candidate.sc` (first-occurrence source-node selection can miss the real
argument-position occurrence when the same source pattern appears twice on one line --
see the review doc, Sec.3) -- discovered specifically BECAUSE this review checked the
real, canonical tool's own output, something R01's self-contained approximation could
never have caught either way.

The corrected, defensible structure, per review:
  - `gates/serialize_dos_verdict.py` (direct, fact-based)        -> canonical CRASH-SAFETY
    subproperty. UNCHANGED, consumed exactly as R01 already did.
  - tchecker-property-adjudicator's taint engine (`adjudicate_js.py` +
    `setup_candidate.sc`/`export_property_propagation.sc`/`export_trace_identity.sc`)
    -> canonical SIZE/STRUCTURE-FLOW subproperty. R02 CONSULTS its real, externally
    produced `evidence_final.json` per candidate site -- it does not reimplement or
    approximate the taint engine's own logic.
  - `serialize_dos_r02.py` (this file)                            -> REDUCER/COORDINATOR
    only. It never decides size/structure on its own; it reads and maps the taint
    engine's own disposition. R01's old `transform_presence.tsv`-based check is kept
    ONLY as an explicitly-labeled, non-authoritative structural pre-filter (see
    `size_structure_structural_prefilter` below) -- useful for deciding which candidate
    sites are worth the cost of a full taint-engine run, never as a substitute verdict.

OPERATIONAL CONTRACT (unchanged from every other property in this session: Joern
invocation is always external to the .py reducer)
------------------------------------------------------------------------------------
For crash-safety, the same three fact tables as R01 (`serialize_sinks.tsv`,
`uncaught_handlers.tsv`, `depth_guards.tsv`, from the existing, frozen, read-only-
consumed `export_serialize_facts.sc`).

For size/structure, ONE `evidence_final.json` per PACKAGE (this coordinator's site
granularity is per-package, matching `setup_candidate.sc`'s own real, disclosed scope
limit of one sink per compiled CPG per run -- see the module docstring's "WHY R02
EXISTS" section above and the manual review doc; a package with more than one
serializer call site needs one taint-engine run per site, keyed the same way), produced
by the EXTERNAL, standard, unmodified pipeline: `jssrc2cpg` -> `setup_candidate.sc`
(srcPattern matching that site's real attacker-source shape) ->
`export_property_propagation.sc` -> `export_trace_identity.sc` -> `adjudicate_js.py`.
When `crash facts` already show `attacker_controlled=false` for a site, the taint
engine is NOT required (both tools trivially agree there is no candidate flow to
check) -- this mirrors real usage cost: only run the expensive interprocedural engine
on sites that are actual candidates.

Every finding still carries `reportable=False`, unconditionally. Pipeline integration
remains explicitly deferred.
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


def _crash_dos_classification(is_attacker, bounded, in_trycatch, depth_guarded, has_net):
    """Verbatim reuse of gates/serialize_dos_verdict.py's guard-precedence logic and
    vocabulary -- UNCHANGED from R01. The direct analyzer remains canonical for
    crash-safety; this function is not touched by the R01->R02 architectural
    correction, which concerns the size/structure axis only."""
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


# Verbatim disposition vocabulary emitted by adjudicate_js.py (see that file's own
# _adjudicate()/Step 6 logic) -> this coordinator's own size/structure vocabulary.
# Kept as an explicit table, not inferred, so a disposition string this module has
# never seen abstains loudly instead of silently falling through.
_TAINT_ENGINE_DISPOSITION_MAP = {
    "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS": "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
    "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT": "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
    "CANDIDATE_OPEN": "ABSTAIN_TAINT_ENGINE_OPEN",
    "REJECTED_NO_STRUCTURAL_FLOW": "SAFE_NO_STRUCTURAL_FLOW",
    "REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED": "SAFE_VALUE_NOT_PRESERVED",
    "RESOLVED_SAFE_BY_ACCEPTED_HINT": "SAFE_BY_ACCEPTED_HINT",
}


def _size_structure_dos_classification(is_attacker, bounded, taint_engine_disposition):
    """Coordinator only -- NEVER computes its own flow verdict. `taint_engine_disposition`
    is the raw disposition string from a real, externally produced evidence_final.json
    (see module docstring); this function does nothing but map it into this module's
    vocabulary and handle the two cases that don't need the taint engine at all."""
    if not is_attacker:
        return "SAFE_NOT_ATTACKER_CONTROLLED"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if taint_engine_disposition is None:
        return "ABSTAIN_NO_TAINT_ENGINE_EVIDENCE"
    return _TAINT_ENGINE_DISPOSITION_MAP.get(
        taint_engine_disposition, "ABSTAIN_UNRECOGNIZED_TAINT_ENGINE_DISPOSITION")


def _structural_prefilter(transform_present, transform_fact_present):
    """R01's OLD intraprocedural approximation, kept ONLY as an explicitly
    non-authoritative pre-filter signal (e.g. "is a full taint-engine run on this site
    even worth its cost"). Never feeds size_structure_dos_classification directly --
    that field is sourced from the real taint engine's own evidence, per the
    architectural correction this revision makes."""
    if not transform_fact_present:
        return "PREFILTER_MISSING_TRANSFORM_FACT"
    if transform_present:
        return "PREFILTER_TRANSFORM_PRESENT_RUN_TAINT_ENGINE"
    return "PREFILTER_DIRECT_FLOW_RUN_TAINT_ENGINE"


def derive(raw, taint_evidence_dir=None):
    raw = Path(raw)
    sinks = _rows(raw / "serialize_sinks.tsv", 8)
    handlers = _rows(raw / "uncaught_handlers.tsv", 2)
    guards = _rows(raw / "depth_guards.tsv", 2)
    transform_path = raw / "transform_presence.tsv"
    transforms = _rows(transform_path, 6) if transform_path.exists() else []

    uncaught_pkgs = {_pkg(h[0]) for h in handlers if h[1] == "uncaughtException"}
    guarded_methods = {(g[0], g[1]) for g in guards}
    transform_by_site = {(t[0], t[1], t[2]): (t[4] == "true", t[5]) for t in transforms}

    taint_evidence_dir = Path(taint_evidence_dir) if taint_evidence_dir else None

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

        taint_disposition = None
        taint_evidence_path = None
        if is_attacker and not bounded and taint_evidence_dir is not None:
            candidate_path = taint_evidence_dir / pkg / "evidence_final.json"
            if candidate_path.exists():
                taint_evidence_path = str(candidate_path)
                taint_disposition = json.loads(candidate_path.read_text())["disposition"]

        crash_cls = _crash_dos_classification(is_attacker, bounded, in_trycatch, depth_guarded, has_net)
        size_cls = _size_structure_dos_classification(is_attacker, bounded, taint_disposition)

        findings.append({
            "file": f_, "package": pkg, "method": meth, "line": line,
            "callee": callee, "arg": arg,
            "attacker_controlled": is_attacker,
            "in_try_catch": in_trycatch,
            "bounded_literal": bounded,
            "depth_guarded": depth_guarded,
            "uncaught_handler_present": has_net,
            "crash_dos_classification": crash_cls,
            "size_structure_dos_classification": size_cls,
            "size_structure_taint_engine_disposition": taint_disposition,
            "size_structure_taint_engine_evidence_path": taint_evidence_path,
            "size_structure_structural_prefilter": _structural_prefilter(transform_present, transform_fact_present),
            "reportable": False,
        })

    return {
        "schema": "serialize-dos-r02/0.1",
        "note": ("Coordinator, not a replacement: crash_dos_classification reuses "
                 "gates/serialize_dos_verdict.py's guard logic verbatim (unchanged "
                 "from R01). size_structure_dos_classification is sourced from the "
                 "REAL tchecker-property-adjudicator taint engine's own "
                 "evidence_final.json disposition (an external, unmodified pipeline "
                 "run per candidate site) -- this module maps that disposition into "
                 "its own vocabulary and never computes a flow verdict itself. "
                 "size_structure_structural_prefilter is R01's old intraprocedural "
                 "approximation, kept ONLY as a non-authoritative pre-filter signal, "
                 "never as the classification. reportable is fixed to false on every "
                 "finding: pipeline integration is explicitly deferred. No "
                 "exploitability, severity, or impact claim is made on either axis."),
        "classification": "SERIALIZE_DOS_CANDIDATE_SET",
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "fixtures/raw",
                             sys.argv[2] if len(sys.argv) > 2 else None), indent=2))
