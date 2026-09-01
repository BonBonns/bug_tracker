#!/usr/bin/env python3
"""REDOS-REDUCE-R01: reduces adjudicate_js.py's own real per-sink evidence_final.json output
into the standard {classification, findings} shape every other npm-pipeline scanner emits.

Real design, per direct instruction (three-tier ReDoS classification for an npm library corpus,
NOT the RocketChat/Express-application corpus the property was originally built against):

  REGEX_COMPLEXITY_CANDIDATE    -- the frozen Stage 1/2 sink+classification logic (UNCHANGED,
                                    export_redos_npm_integ.sc's own verbatim copy of
                                    export_redos_integ.sc) identified a DANGEROUS regex operation.
  PACKAGE_API_INPUT_REACHABLE   -- a value from this package's OWN exported (CommonJS/ESM)
                                    function parameter reaches that operation. THE appropriate
                                    initial boundary for an npm LIBRARY (its own public API
                                    surface is externally-supplied input) -- called
                                    "externally supplied package input", never "attacker-
                                    controlled" or "a vulnerability".
  APPLICATION_INGRESS_REACHABLE -- the frozen Meteor.methods/req.*/message.* source model
                                    (unchanged, a SEPARATE adapter, never generalized into the
                                    npm rule) also reaches it. Strengthens a record; NEVER
                                    required on its own.

A finding is emitted ONLY when BOTH REGEX_COMPLEXITY_CANDIDATE and PACKAGE_API_INPUT_REACHABLE
hold -- an npm library's own dangerous-but-unreached-from-its-public-API regex, or one reached
ONLY via a web-framework-specific source this package doesn't itself define, is correctly never
promoted to a candidate here (it may still be true, but is not "an npm library's own scanner
candidate" under this property's own current, disclosed scope).

Input contract:
  redos_verdict.py <raw_dir> <src_dir> <out.json>
    raw_dir  -- already-produced by export_redos_npm_integ.sc: source_facts.tsv,
                propagation_relations.tsv, property_outcome.tsv, transform_identity.tsv (Joern
                invocation itself is a SEPARATE step, not this script's job -- this is a reducer,
                not a producer-orchestrator, matching every other npm-pipeline scanner's own
                <raw_dir> <out.json> convention plus the one real additional input this specific
                property genuinely needs: TCH_SRC, exactly like run_pipeline_one.py already keeps
                pkg_dir around for provenance.enrich_record's own same real reason).
    src_dir  -- the package's own pristine source tree (adjudicate_js.py's own TCH_SRC; used for
                real code-context reads, e.g. line_of()/func_src()).
    out.json -- written: {"classification": {...counts...}, "findings": [...]}.

Why this reads source_facts.tsv DIRECTLY, not solely evidence_final.json: adjudicate_js.py's own
`build_evidence_v0()` only ever surfaces `srcf[0]`'s own origin_family (the FIRST source
alternative row) into evidence_final.json's own `structural__ESTABLISHED_BY_STATIC_ANALYSIS.
origin.origin_family` field -- confirmed by direct inspection of adjudicate_js.py's own source
(`"origin_family": srcf[0][3]`). A sink reached by BOTH source families would have its second
family's own membership silently dropped if this reducer only read evidence_final.json's own
origin field. Reading source_facts.tsv directly for ALL of a sink's own alternatives -- which
export_redos_npm_integ.sc already tags per-row via column 4 (confirmed, by direct inspection,
to be a free-text field adjudicate_js.py never filters or interprets, only carries through) --
recovers the full, real per-family membership adjudicate_js.py's own single-origin summary loses.

reportable is HARDCODED False in every finding this reduces, per direct instruction: "Keep it
non-reportable initially. Enable reporting only after a real npm package exercises the complete
exported-input-to-regex path and survives manual review." Never computed by any gate here.
"""
import base64
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADJUDICATOR_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/adjudicator")
PROPERTY_CONFIG = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/property_configs/redos_complexity.json")
NO_HINTS = os.path.join(ADJUDICATOR_DIR, "no_hints.json")

PACKAGE_API_FAMILY = "PACKAGE_API_INPUT"
APPLICATION_INGRESS_FAMILY = "APPLICATION_INGRESS"


def _read_tsv(path, n):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path) as f:
        for ln in f:
            if not ln.strip():
                continue
            parts = ln.rstrip("\n").split("\t")
            if len(parts) == n:
                out.append(parts)
    return out


def families_by_sink(raw_dir):
    """sink_id -> set of origin_family values present among its own ESTABLISHED source rows
    (ALL alternatives, not just adjudicate_js.py's own srcf[0] -- see module docstring)."""
    rows = _read_tsv(os.path.join(raw_dir, "source_facts.tsv"), 12)
    out = {}
    for r in rows:
        sink_id, family, status = r[0], r[3], r[4]
        if status != "ESTABLISHED":
            continue
        out.setdefault(sink_id, set()).add(family)
    return out


def sink_lines(raw_dir):
    """sink_id -> line number, read directly from source_facts.tsv (column 1) -- avoids a second
    Joern query; every row for a given sink already carries its own real sink line."""
    rows = _read_tsv(os.path.join(raw_dir, "source_facts.tsv"), 12)
    out = {}
    for r in rows:
        out.setdefault(r[0], r[1])
    return out


def run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir):
    if os.path.isdir(out_dir):
        for fn in os.listdir(out_dir):
            os.remove(os.path.join(out_dir, fn))
    os.makedirs(out_dir, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "TCH_RAW": raw_dir,
        "TCH_SRC": src_dir,
        "TCH_OUT": out_dir,
        "TCH_SINK": sink_id,
        "TCH_PROPERTY_CONFIG": PROPERTY_CONFIG,
        "TCH_HINTS": NO_HINTS,
        "TCH_FINDING": "redos_npm_candidate.js",
    })
    r = subprocess.run([sys.executable, "adjudicate_js.py"], cwd=ADJUDICATOR_DIR, env=env,
                        capture_output=True, text=True, timeout=120)
    evidence_path = os.path.join(out_dir, "evidence_final.json")
    if not os.path.isfile(evidence_path):
        return None, r.stdout + r.stderr
    with open(evidence_path) as f:
        return json.load(f), None


def emit_findings(raw_dir, src_dir, work_dir):
    fams = families_by_sink(raw_dir)
    lines = sink_lines(raw_dir)
    classification = {
        "SINKS_WITH_ANY_ESTABLISHED_SOURCE": len(fams),
        "PACKAGE_API_INPUT_REACHABLE": 0,
        "APPLICATION_INGRESS_ONLY_NOT_PROMOTED": 0,
        "ADJUDICATOR_RUN_FAILED": 0,
    }
    findings = []
    for sink_id in sorted(fams):
        families = fams[sink_id]
        if PACKAGE_API_FAMILY not in families:
            # per direct instruction: APPLICATION_INGRESS_REACHABLE alone is not a candidate for
            # an npm library -- real, disclosed, never silently promoted.
            classification["APPLICATION_INGRESS_ONLY_NOT_PROMOTED"] += 1
            continue
        out_dir = os.path.join(work_dir, f"adj_{sink_id}")
        evidence, err = run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir)
        if evidence is None:
            classification["ADJUDICATOR_RUN_FAILED"] += 1
            findings.append({
                "property": "REDOS",
                "sink_node_id": sink_id,
                "sink_line": int(lines.get(sink_id, -1)),
                "classification": "PACKAGE_API_INPUT_REACHABLE",
                "regex_complexity": "CANDIDATE",
                "source_boundary": "EXPORTED_FUNCTION_PARAMETER",
                "application_ingress": ("ESTABLISHED" if APPLICATION_INGRESS_FAMILY in families
                                         else "NOT_ESTABLISHED"),
                "adjudicator_status": "RUN_FAILED",
                "adjudicator_error": (err or "")[-2000:],
                "reportable": False,
            })
            continue
        classification["PACKAGE_API_INPUT_REACHABLE"] += 1
        findings.append({
            "property": "REDOS",
            "sink_node_id": sink_id,
            "sink_line": evidence.get("sink", {}).get("line", int(lines.get(sink_id, -1))),
            "finding_id": evidence.get("finding_id"),
            "classification": "PACKAGE_API_INPUT_REACHABLE",
            "regex_complexity": "CANDIDATE",
            "source_boundary": "EXPORTED_FUNCTION_PARAMETER",
            "application_ingress": ("ESTABLISHED" if APPLICATION_INGRESS_FAMILY in families
                                     else "NOT_ESTABLISHED"),
            "adjudicator_disposition": evidence.get("disposition"),
            "adjudicator_property_outcome": evidence.get("property_outcome"),
            "reportable": False,
        })
    return classification, findings


def main():
    if len(sys.argv) != 4:
        print("usage: redos_verdict.py <raw_dir> <src_dir> <out.json>", file=sys.stderr)
        sys.exit(2)
    raw_dir, src_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    work_dir = out_path + ".work"
    os.makedirs(work_dir, exist_ok=True)
    classification, findings = emit_findings(raw_dir, src_dir, work_dir)
    with open(out_path, "w") as f:
        json.dump({"classification": classification, "findings": findings}, f, indent=2)
    print(json.dumps({"classification": classification, "n_findings": len(findings)}, indent=2))


if __name__ == "__main__":
    main()
