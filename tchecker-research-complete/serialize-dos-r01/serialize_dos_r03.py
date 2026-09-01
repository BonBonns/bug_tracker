#!/usr/bin/env python3
"""SERIALIZE-DOS-R03 -- source-occurrence correction, published because it changes the
canonical size/structure-flow evidence.

WHY R03 EXISTS
--------------
R02's coordinator (`serialize_dos_r02.py`) sourced `size_structure_dos_classification`
from the REAL taint engine's own `evidence_final.json` disposition -- correct
architecture, but it still ran the taint engine through the FROZEN
`setup_candidate.sc`, which selects the sink via `cpg.call.name("stringify")
.headOption` and the source via `cpg.call.codeExact(srcPattern).headOption` -- both
single, arbitrary "first" picks. On the real `motifer@26.1.1` package, the source
pattern `req.body` appears twice at the same call site (once as a ternary's condition,
once as the argument actually passed to the sink); `.headOption` picked the
non-flowing condition, so R02's coordinator inherited a false `NO_FLOW` from the
canonical engine itself -- "a coordinator cannot correct missing upstream evidence."

`producers/setup_candidate_multisource.sc` (NEW; the frozen `setup_candidate.sc` is
untouched) fixes this at the source: it enumerates EVERY matching sink and EVERY
matching source occurrence, computes a real dataflow for the complete cross-product,
and writes only the (sink, source) pairs with a real flow into the SAME legacy schema
`setup_candidate.sc` always wrote -- so the FROZEN
`export_property_propagation.sc`/`export_trace_identity.sc`/`adjudicate_js.py` run
completely unmodified downstream. See that file's own docstring and
`check_setup_candidate_multisource.py` (9 real-Joern-compiled controls, including the
real `motifer@26.1.1` package reproducing the correct evidence automatically) for the
full fix and its validation.

R03's own change from R02 is therefore narrow and entirely about WHICH pipeline run
produced the `evidence_final.json` this coordinator reads: identical shape, identical
mapping table, identical `crash_dos_classification` (still reused verbatim from
`gates/serialize_dos_verdict.py`, untouched) -- only the SOURCE of the size/structure
evidence changes, from the old single-source `setup_candidate.sc` run to the new
`setup_candidate_multisource.sc` run. See `R03_RESULTS.md` for why this counts as
"changing the canonical evidence" (motifer's size axis flips from an unreachable
`NO_FLOW` artifact to a real, automatically-reproduced `ESTABLISHED`) and is therefore
published as a new revision rather than folded quietly into R02.

MANUAL ADJUDICATION IS NOT ENCODED HERE
-----------------------------------------
Per the manual review of motifer (`study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md`),
motifer's crash-safety finding was adjudicated REJECTED (a real Express dispatch-layer
catch boundary, not modeled by `gates/serialize_dos_verdict.py`), and its size/structure
finding was recorded with a four-tag classification narrower than a flat "confirmed"
verdict. NEITHER of those manual conclusions is baked into this module's automated
output: `crash_dos_classification` still mechanically reports whatever
`gates/serialize_dos_verdict.py`'s guard model says (`CANDIDATE_UNGUARDED_SERIALIZE_DOS`
for motifer, unchanged -- the crash-safety analyzer was not modified by this
correction), and `size_structure_dos_classification` still just maps the real taint
engine's raw disposition. Manual review is a separate, human-level adjudication layer,
documented separately, never silently encoded into the mechanical coordinator -- exactly
the same principle R02 already established.
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
    """Verbatim reuse of gates/serialize_dos_verdict.py's guard-precedence logic --
    UNCHANGED from R01/R02. This revision does not touch the crash-safety subproperty
    at all; motifer's real crash-safety adjudication (REJECTED, an Express dispatch
    boundary this function has no model of) lives only in the manual review document,
    never here."""
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


# Unchanged from R02 -- see that module for why each mapping is what it is.
_TAINT_ENGINE_DISPOSITION_MAP = {
    "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS": "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
    "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT": "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE",
    "CANDIDATE_OPEN": "ABSTAIN_TAINT_ENGINE_OPEN",
    "REJECTED_NO_STRUCTURAL_FLOW": "SAFE_NO_STRUCTURAL_FLOW",
    "REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED": "SAFE_VALUE_NOT_PRESERVED",
    "RESOLVED_SAFE_BY_ACCEPTED_HINT": "SAFE_BY_ACCEPTED_HINT",
}


def _size_structure_dos_classification(is_attacker, bounded, taint_engine_disposition):
    """Unchanged from R02: still a pure coordinator, never computes its own flow
    verdict. `taint_engine_disposition` now comes from a run of the CORRECTED
    setup_candidate_multisource.sc pipeline (see module docstring) rather than the old
    single-source setup_candidate.sc -- that is the entire R02->R03 delta."""
    if not is_attacker:
        return "SAFE_NOT_ATTACKER_CONTROLLED"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if taint_engine_disposition is None:
        return "ABSTAIN_NO_TAINT_ENGINE_EVIDENCE"
    return _TAINT_ENGINE_DISPOSITION_MAP.get(
        taint_engine_disposition, "ABSTAIN_UNRECOGNIZED_TAINT_ENGINE_DISPOSITION")


def _structural_prefilter(transform_present, transform_fact_present):
    """R01's old intraprocedural approximation -- kept ONLY as a non-authoritative
    pre-filter signal, unchanged from R02."""
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
        "schema": "serialize-dos-r03/0.1",
        "note": ("Same coordinator shape as R02 (crash axis reused verbatim from "
                 "gates/serialize_dos_verdict.py; size axis sourced from the real "
                 "taint engine's own evidence_final.json, never computed here) -- the "
                 "R02->R03 change is entirely in WHICH pipeline run produced that "
                 "evidence: setup_candidate_multisource.sc (enumerates every "
                 "sink/source occurrence, never an arbitrary first pick) instead of "
                 "the frozen setup_candidate.sc (single first-occurrence picks on "
                 "both sides). reportable is fixed to false on every finding: "
                 "pipeline integration is explicitly deferred. Manual adjudication "
                 "(e.g. motifer's crash-safety REJECTED finding, or its four-tag "
                 "size/structure record) is NOT encoded in this module's output -- "
                 "see study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md. No "
                 "exploitability, severity, or impact claim is made on either axis."),
        "classification": "SERIALIZE_DOS_CANDIDATE_SET",
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "fixtures/raw",
                             sys.argv[2] if len(sys.argv) > 2 else None), indent=2))
