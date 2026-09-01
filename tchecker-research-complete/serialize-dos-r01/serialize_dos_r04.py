#!/usr/bin/env python3
"""SERIALIZE-DOS-R04 -- two explicitly separate external-input source families, and
terminology corrected to stop overstating what the mechanical proof establishes.

WHY R04 EXISTS
--------------
Three real npm packages in a row (mozilla/fxa's customs.js, @sonatel-os/juf-xpress-
logger, @rasla/logify) exposed the same limitation: R01-R03's size/structure engine
recognized APPLICATION-INGRESS sources (req.body, request.payload) but had no model at
all for a value arriving as an already-abstracted EXPORTED FUNCTION OR METHOD
PARAMETER -- this package's own public npm API surface. Per instruction, that model is
NOT invented from scratch here: the ReDoS property (finished, merged into develop) had
already built and real-package-validated exactly this recognition. R04's new producer,
`producers/npm_public_export_sources_r04.sc`, PORTS that model's resolution algorithm
(export_redos_npm_integ_r02.sc's capabilities 1-3: exported class instance methods,
object-literal shorthand exports, constructor-parameter this.field identity chains)
verbatim, re-pointed at this property's own sinks. See that producer's own docstring
for the full port rationale and its real, disclosed limitations (most notably: a
whole-program reachableByFlows check across a closure boundary can flag a captured but
semantically-unrelated variable as "reaching" a sink -- observed directly on the real
motifer package, see R04_RESULTS.md Sec.3).

TWO EXPLICITLY SEPARATE FAMILIES, NEVER MERGED
------------------------------------------------
  APPLICATION_INGRESS_INPUT  -- R01-R03's own model, unchanged: req.body/request.payload-
    shaped literal accessor patterns.
  PACKAGE_API_INPUT  -- NEW: exported function/method parameters and constructor-
    parameter this.field chains, tracked through structural identities and uniquely
    resolved calls (never a name-based guess).
A sink's family membership is read directly from the new producer's own
source_facts.tsv (one ESTABLISHED row per (sink, source, family) triple) -- NEVER from
adjudicate_js.py's own single "origin_family" narrative field, which was directly
observed picking an ARBITRARY one of the two families when a sink has flows from both
(motifer's own sink, again -- see R04_RESULTS.md Sec.3.1). This reducer computes family
presence independently and reports both flags on every finding.

CRASH-SAFETY AXIS: SCOPE UNCHANGED, DISCLOSED
------------------------------------------------
`crash_dos_classification` still reuses gates/serialize_dos_verdict.py's guard logic
verbatim and is STILL scoped to APPLICATION_INGRESS_INPUT only -- the crash-DoS fact
producer (export_serialize_facts.sc) has no model of exported-parameter sources at all,
and extending it is out of scope for this revision (which targets the size/structure
engine's source model, per instruction). A PACKAGE_API_INPUT-only finding (no ingress
source at all) always reports crash_dos_classification=NO_SUPPORTED_EXTERNAL_INPUT_FLOW,
even when the size axis independently finds a real PACKAGE_API_INPUT candidate at the
very same sink -- this is a real, disclosed scope split between the two axes, not an
oversight: crash-safety in this revision answers "is this reachable via ingress", not
"is this reachable at all".

TERMINOLOGY CORRECTIONS (required, applied everywhere in this module)
------------------------------------------------------------------------
  CANDIDATE_UNBOUNDED_SERIALIZE_SIZE   -> CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED
    "Unbounded" claimed more than the mechanical proof established: the analyzer proves
    a flow exists and that no PACKAGE-LOCAL bound was found on it -- it cannot, and does
    not, rule out an upstream, external, configurable bound (motifer's own body-parser
    default is exactly this case -- present, real, but not analyzer-verifiable, and
    never treated as proof of a package-local bound).
  SAFE_NOT_ATTACKER_CONTROLLED         -> NO_SUPPORTED_EXTERNAL_INPUT_FLOW
    "Safe" claimed a security property; what is actually established is narrower and
    purely structural: no source this revision's supported families and detection
    reach the sink -- not a safety guarantee (an unsupported source shape, e.g. ES5
    prototype-assignment methods -- already disclosed, real, out of scope -- could still
    exist and simply not be recognized).
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


_FAMILY_APPLICATION_INGRESS = "APPLICATION_INGRESS_INPUT"
_FAMILY_PACKAGE_API = "PACKAGE_API_INPUT"


def _families_at_line(npm_source_facts_dir, pkg, line):
    """Reads source_facts.tsv from a prior npm_public_export_sources_r04.sc run for this
    package, returns the set of families with an ESTABLISHED row at this sink line.
    Join key is (package, line) -- this coordinator's site granularity remains
    per-package/per-line, the same disclosed scope as R02/R03's per-package taint-engine
    evidence lookup (one relevant sink per package in every case validated so far;
    a package with multiple same-line sinks would need finer-grained matching, not
    encountered in this revision's real-package evidence)."""
    if npm_source_facts_dir is None:
        return set()
    p = Path(npm_source_facts_dir) / pkg / "source_facts.tsv"
    if not p.exists():
        return set()
    families = set()
    for ln in p.read_text().splitlines():
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) >= 5 and xs[1] == str(line) and xs[4] == "ESTABLISHED":
            families.add(xs[3])
    return families


def _crash_dos_classification(is_ingress_attacker, bounded, in_trycatch, depth_guarded, has_net):
    """Verbatim reuse of gates/serialize_dos_verdict.py's guard-precedence logic --
    unchanged from R01-R03. STILL scoped to APPLICATION_INGRESS_INPUT only (see module
    docstring's "CRASH-SAFETY AXIS" section) -- `is_ingress_attacker` comes only from
    the crash-DoS fact producer's own regex-based ingress detection, never from
    PACKAGE_API_INPUT family membership."""
    if not is_ingress_attacker:
        return "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if in_trycatch:
        return "SAFE_TRY_CATCH"
    if depth_guarded:
        return "SAFE_DEPTH_GUARDED"
    if has_net:
        return "SUSPICIOUS_UNGUARDED_SERIALIZE"
    return "CANDIDATE_UNGUARDED_SERIALIZE_DOS"


_TAINT_ENGINE_DISPOSITION_MAP = {
    "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS": "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
    "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT": "CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED",
    "CANDIDATE_OPEN": "ABSTAIN_TAINT_ENGINE_OPEN",
    "REJECTED_NO_STRUCTURAL_FLOW": "SAFE_NO_STRUCTURAL_FLOW",
    "REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED": "SAFE_VALUE_NOT_PRESERVED",
    "RESOLVED_SAFE_BY_ACCEPTED_HINT": "SAFE_BY_ACCEPTED_HINT",
}


def _size_structure_dos_classification(families_present, bounded, taint_engine_disposition):
    """Coordinator only -- never computes its own flow verdict. `families_present` is
    computed independently by THIS module (see module docstring on why
    adjudicate_js.py's own narrative origin_family field is not trusted for this).
    A sink with NEITHER family present never needed a taint-engine run at all."""
    if not families_present:
        return "NO_SUPPORTED_EXTERNAL_INPUT_FLOW"
    if bounded:
        return "SAFE_BOUNDED_LITERAL"
    if taint_engine_disposition is None:
        return "ABSTAIN_NO_TAINT_ENGINE_EVIDENCE"
    return _TAINT_ENGINE_DISPOSITION_MAP.get(
        taint_engine_disposition, "ABSTAIN_UNRECOGNIZED_TAINT_ENGINE_DISPOSITION")


def derive(raw, npm_source_facts_dir=None, taint_evidence_dir=None):
    raw = Path(raw)
    sinks = _rows(raw / "serialize_sinks.tsv", 8)
    handlers = _rows(raw / "uncaught_handlers.tsv", 2)
    guards = _rows(raw / "depth_guards.tsv", 2)

    uncaught_pkgs = {_pkg(h[0]) for h in handlers if h[1] == "uncaughtException"}
    guarded_methods = {(g[0], g[1]) for g in guards}

    npm_source_facts_dir = Path(npm_source_facts_dir) if npm_source_facts_dir else None
    taint_evidence_dir = Path(taint_evidence_dir) if taint_evidence_dir else None

    findings = []
    for f_, meth, line, callee, arg, attacker, in_try, bounded_lit in sinks:
        pkg = _pkg(f_)
        is_ingress_attacker = attacker == "true"
        in_trycatch = in_try == "true"
        bounded = bounded_lit == "true"
        depth_guarded = (f_, meth) in guarded_methods
        has_net = pkg in uncaught_pkgs

        families = _families_at_line(npm_source_facts_dir, pkg, line)
        # the crash-DoS producer's own ingress detection is folded in too, in case the
        # npm-source-facts run wasn't supplied for this exact site (keeps R01-R03's
        # ingress-only behavior available standalone, per the disclosed scope note).
        if is_ingress_attacker and not bounded:
            families = families | {_FAMILY_APPLICATION_INGRESS}

        taint_disposition = None
        taint_evidence_path = None
        if families and not bounded and taint_evidence_dir is not None:
            candidate_path = taint_evidence_dir / pkg / "evidence_final.json"
            if candidate_path.exists():
                taint_evidence_path = str(candidate_path)
                taint_disposition = json.loads(candidate_path.read_text())["disposition"]

        crash_cls = _crash_dos_classification(is_ingress_attacker, bounded, in_trycatch, depth_guarded, has_net)
        size_cls = _size_structure_dos_classification(families, bounded, taint_disposition)

        findings.append({
            "file": f_, "package": pkg, "method": meth, "line": line,
            "callee": callee, "arg": arg,
            "crash_dos_classification": crash_cls,
            "size_structure_dos_classification": size_cls,
            "external_input_families": sorted(families),
            "size_structure_taint_engine_disposition": taint_disposition,
            "size_structure_taint_engine_evidence_path": taint_evidence_path,
            "reportable": False,
        })

    return {
        "schema": "serialize-dos-r04/0.1",
        "note": ("Two explicitly separate external-input source families -- "
                 "APPLICATION_INGRESS_INPUT (R01-R03's own model, unchanged) and "
                 "PACKAGE_API_INPUT (new: exported function/method parameters and "
                 "constructor this.field chains, ported from the finished ReDoS "
                 "property's own npm public-export source model) -- computed "
                 "independently by this module from the new producer's own "
                 "source_facts.tsv, never from adjudicate_js.py's own single "
                 "origin_family narrative field (observed to pick an arbitrary one of "
                 "two present families). crash_dos_classification remains scoped to "
                 "APPLICATION_INGRESS_INPUT only (disclosed, unchanged). Terminology "
                 "corrected: CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED (was "
                 "CANDIDATE_UNBOUNDED_SERIALIZE_SIZE) and "
                 "NO_SUPPORTED_EXTERNAL_INPUT_FLOW (was SAFE_NOT_ATTACKER_CONTROLLED) "
                 "-- neither claims more than the mechanical proof establishes. "
                 "reportable is fixed to false on every finding: pipeline integration "
                 "is explicitly deferred. No exploitability, severity, or impact claim "
                 "is made on either axis."),
        "classification": "SERIALIZE_DOS_CANDIDATE_SET",
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "fixtures/raw",
                             sys.argv[2] if len(sys.argv) > 2 else None,
                             sys.argv[3] if len(sys.argv) > 3 else None), indent=2))
