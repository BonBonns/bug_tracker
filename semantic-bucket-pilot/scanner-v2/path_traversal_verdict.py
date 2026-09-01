#!/usr/bin/env python3
"""PATH-TRAV-REDUCE-R01: reduces export_path_traversal_integ_r01.sc's own real raw facts (plus,
for each promoted sink, a real adjudicate_js.py run against property_configs/path_traversal_host.json
-- unchanged, read-only) into the standard {classification, findings} shape every other pipeline
scanner emits, matching redos_verdict.py's own structural model (same `<raw_dir> <src_dir>
<out.json>` CLI contract, same "read source_facts.tsv directly for ALL of a sink's alternatives
rather than trusting adjudicate_js.py's own single-origin evidence_final.json summary" design --
confirmed necessary here too: adjudicate_js.py's own `origin.origin_family` field is built from
`srcf[0][3]`, the FIRST source row only, for the exact same reason redos_verdict.py's own docstring
describes).

Real design (three-tier classification, adapted from ReDoS's own REGEX_COMPLEXITY_CANDIDATE /
PACKAGE_API_INPUT_REACHABLE / APPLICATION_INGRESS_REACHABLE shape to this property):

  FILESYSTEM_SINK_CANDIDATE      -- export_path_traversal_integ_r01.sc's own Stage-1 sink-family
                                     recognition (FS_READ/FS_WRITE/FS_DELETE/EXPRESS_SEND_FILE/
                                     EXPRESS_DOWNLOAD, structurally import-binding-aware, see the
                                     producer's own header comment) identified a real sink AND at
                                     least one source alternative reaches it (source_facts.tsv row
                                     with status ESTABLISHED for that sink_id).
  PACKAGE_API_INPUT_REACHABLE    -- a value from THIS package's own exported (CommonJS/ESM)
                                     function parameter reaches the sink -- "externally supplied
                                     package input", never "attacker-controlled" or "a vulnerability".
  APPLICATION_INGRESS_REACHABLE  -- the frozen Meteor.methods/req.*/message.* application-boundary
                                     source model also reaches it.

UNLIKE redos_verdict.py's npm-library-only design (which requires PACKAGE_API_INPUT_REACHABLE and
never promotes an APPLICATION_INGRESS_REACHABLE-only sink), this property serves BOTH an npm-package
context AND the application-deployment context this property was originally built against
(RocketChat/Meteor) -- per the audit's own item 2 finding, APPLICATION_INGRESS_INPUT is this
property's PRE-EXISTING, already-verified source tier, not a secondary one. So EITHER family alone
is sufficient to reach FILESYSTEM_SINK_CANDIDATE status here; both families are still independently,
distinctly tagged in every finding (never merged), so a downstream consumer can filter to the
npm-package-only subset later if a future phase needs ReDoS's own stricter promotion rule.

A THIRD axis this property adds beyond ReDoS's own two: containment_status, read directly from
property_outcome.tsv (keyed by (sink_id, origin_id), not merely `srcf[0]`) --
  BROKEN       -- containment genuinely proven (fixed Express root; canonicalized+boundary-aware
                  base check; a structurally-proven containment wrapper) for THIS (sink, origin)
                  alternative -- NEVER emitted as a finding; a genuinely resolved-safe alternative.
  OPEN         -- an on-path transform/wrapper this producer cannot verify one way or the other
                  (unresolved wrapper callee, LOOKUP_KEY_INFLUENCE, or an unrecognized on-path
                  transform such as a literal '..' strip) -- emitted, needs review.
  ESTABLISHED  -- no containment proof found at all (including every WEAK/insufficient shape --
                  bare .startsWith/.includes, a literal '..' strip, path.normalize alone, a
                  user-controlled Express root -- all correctly demoted to non-proof by the R01
                  producer, see its own header comment) -- emitted, the primary candidate shape.
weak_diagnostic_guards (source_facts.tsv column 6, '|'-joined) is carried through into every
finding verbatim, whatever its containment_status, as a REVIEWER-FACING diagnostic note -- it never
changes the classification or containment_status itself (per direct instruction: a weak guard must
never silently promote a finding away from "not proven safe").

Input contract:
  path_traversal_verdict.py <raw_dir> <src_dir> <out.json>
    raw_dir  -- already produced by export_path_traversal_integ_r01.sc: source_facts.tsv,
                propagation_relations.tsv, property_outcome.tsv, transform_identity.tsv.
    src_dir  -- the package's own pristine source tree (adjudicate_js.py's own TCH_SRC).
    out.json -- written: {"classification": {...counts...}, "findings": [...]}.

reportable is HARDCODED False in every finding this reduces, per direct instruction ("keep it
non-reportable initially ... this phase stops at a standalone, frozen property + real-package
validation"). Never computed by any gate here, and never wired into provenance.py/
staged_enablement.py/any aggregator -- this reducer is a standalone consumer of its own producer's
raw facts only.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADJUDICATOR_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/adjudicator")
PROPERTY_CONFIG = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/property_configs/path_traversal_host.json")
NO_HINTS = os.path.join(ADJUDICATOR_DIR, "no_hints.json")

PACKAGE_API_FAMILY = "PACKAGE_API_INPUT"
APPLICATION_INGRESS_FAMILY = "APPLICATION_INGRESS_INPUT"

SF_COLS = 12   # source_facts.tsv: sink_id, sink_line, src_id, origin_family, status, sink_family,
               # weak_diagnostic_guards, then 5 reserved-blank columns (see the producer's own
               # emission comment -- adjudicate_js.py itself only ever reads columns 0-4).
PO_COLS = 5    # property_outcome.tsv: sink_id, origin_id, outcome, -1, -1


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


def alternatives_by_sink(raw_dir):
    """sink_id -> list of (origin_id, origin_line, origin_code, origin_family, sink_family,
    weak_diagnostic_guards) for every ESTABLISHED (reachable) source alternative -- ALL of them,
    not just source_facts.tsv's own first row, matching redos_verdict.py's own confirmed reason
    for reading this file directly rather than trusting evidence_final.json's single-origin summary."""
    rows = _read_tsv(os.path.join(raw_dir, "source_facts.tsv"), SF_COLS)
    out = {}
    for r in rows:
        sink_id, sink_line, src_id, family, status, sink_family, weak = (
            r[0], r[1], r[2], r[3], r[4], r[5], r[6])
        if status != "ESTABLISHED":
            continue
        out.setdefault(sink_id, []).append({
            "origin_id": src_id, "origin_family": family, "sink_line": sink_line,
            "sink_family": sink_family,
            "weak_diagnostic_guards": [w for w in weak.split("|") if w],
        })
    return out


def origin_lines_and_codes(raw_dir):
    """(sink_id, origin_id) -> (line, code), read from propagation_relations.tsv directly (columns
    0=sink_id, 3=origin_id, 4=origin_line, 5=origin_code) -- avoids a second Joern query."""
    rows = _read_tsv(os.path.join(raw_dir, "propagation_relations.tsv"), 9)
    out = {}
    for r in rows:
        out[(r[0], r[3])] = (r[4], r[5])
    return out


def containment_status(raw_dir):
    """(sink_id, origin_id) -> outcome (BROKEN/OPEN/ESTABLISHED), read directly from
    property_outcome.tsv -- per-alternative, not the single `srcf[0]`-derived summary
    adjudicate_js.py's own evidence_final.json would give."""
    rows = _read_tsv(os.path.join(raw_dir, "property_outcome.tsv"), PO_COLS)
    out = {}
    for r in rows:
        out[(r[0], r[1])] = r[2]
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
        "TCH_FINDING": "path_traversal_r01_candidate.js",
    })
    r = subprocess.run([sys.executable, "adjudicate_js.py"], cwd=ADJUDICATOR_DIR, env=env,
                        capture_output=True, text=True, timeout=120)
    evidence_path = os.path.join(out_dir, "evidence_final.json")
    if not os.path.isfile(evidence_path):
        return None, r.stdout + r.stderr
    with open(evidence_path) as f:
        return json.load(f), None


def emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=True):
    alts = alternatives_by_sink(raw_dir)
    lines_codes = origin_lines_and_codes(raw_dir)
    outcomes = containment_status(raw_dir)

    classification = {
        "FILESYSTEM_SINK_CANDIDATE": len(alts),
        "PACKAGE_API_INPUT_REACHABLE": 0,
        "APPLICATION_INGRESS_REACHABLE": 0,
        "ALTERNATIVES_BROKEN_EXCLUDED": 0,   # genuinely proven contained -- never a finding
        "ALTERNATIVES_ESTABLISHED": 0,
        "ALTERNATIVES_OPEN": 0,
        "ADJUDICATOR_RUN_FAILED": 0,
    }
    findings = []
    for sink_id in sorted(alts):
        alternatives = alts[sink_id]
        families_here = {a["origin_family"] for a in alternatives}
        if PACKAGE_API_FAMILY in families_here:
            classification["PACKAGE_API_INPUT_REACHABLE"] += 1
        if APPLICATION_INGRESS_FAMILY in families_here:
            classification["APPLICATION_INGRESS_REACHABLE"] += 1

        evidence = None
        adjudicator_error = None
        if run_adjudicator:
            out_dir = os.path.join(work_dir, f"adj_{sink_id}")
            evidence, adjudicator_error = run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir)
            if evidence is None:
                classification["ADJUDICATOR_RUN_FAILED"] += 1

        for alt in alternatives:
            key = (sink_id, alt["origin_id"])
            outcome = outcomes.get(key, "ESTABLISHED")
            if outcome == "BROKEN":
                classification["ALTERNATIVES_BROKEN_EXCLUDED"] += 1
                continue  # genuinely proven safe -- never surfaced as a finding
            classification["ALTERNATIVES_ESTABLISHED" if outcome == "ESTABLISHED" else "ALTERNATIVES_OPEN"] += 1
            line, code = lines_codes.get(key, (alt["sink_line"], ""))
            findings.append({
                "property": "PATH_TRAVERSAL",
                "sink_node_id": sink_id,
                "sink_line": int(alt["sink_line"]),
                "sink_family": alt["sink_family"],
                "origin_node_id": alt["origin_id"],
                "origin_line": int(line) if str(line).lstrip("-").isdigit() else -1,
                "origin_code": code,
                "origin_family": alt["origin_family"],
                "classification": "FILESYSTEM_SINK_CANDIDATE",
                "containment_status": outcome,
                "weak_diagnostic_guards": alt["weak_diagnostic_guards"],
                "package_api_input": "ESTABLISHED" if PACKAGE_API_FAMILY in families_here else "NOT_ESTABLISHED",
                "application_ingress": "ESTABLISHED" if APPLICATION_INGRESS_FAMILY in families_here else "NOT_ESTABLISHED",
                "adjudicator_disposition": evidence.get("disposition") if evidence else None,
                "adjudicator_property_outcome": evidence.get("property_outcome") if evidence else None,
                "adjudicator_status": "OK" if evidence else ("RUN_FAILED" if run_adjudicator else "SKIPPED"),
                "adjudicator_error": (adjudicator_error or "")[-2000:] if adjudicator_error else None,
                "reportable": False,
            })
    return classification, findings


def main():
    if len(sys.argv) != 4:
        print("usage: path_traversal_verdict.py <raw_dir> <src_dir> <out.json>", file=sys.stderr)
        sys.exit(2)
    raw_dir, src_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    work_dir = out_path + ".work"
    os.makedirs(work_dir, exist_ok=True)
    run_adjudicator = os.environ.get("PT_VERDICT_SKIP_ADJUDICATOR") != "1"
    classification, findings = emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=run_adjudicator)
    with open(out_path, "w") as f:
        json.dump({"classification": classification, "findings": findings}, f, indent=2)
    print(json.dumps({"classification": classification, "n_findings": len(findings)}, indent=2))


if __name__ == "__main__":
    main()
