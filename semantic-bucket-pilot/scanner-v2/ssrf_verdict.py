#!/usr/bin/env python3
"""SSRF-REDUCE-R01: reduces export_ssrf_integ.sc's own real raw facts (plus, for each candidate
sink, a real adjudicate_js.py run against property_configs/ssrf_host.json -- unchanged, read-only)
into the standard {classification, findings} shape every other npm-pipeline scanner emits,
matching path_traversal_verdict.py's own structural model most closely of any prior reducer (same
`<raw_dir> <src_dir> <out.json>` CLI contract, same real per-alternative BROKEN/OPEN/ESTABLISHED
containment_status read from property_outcome.tsv -- export_ssrf_integ.sc already computes this
tiering itself in Scala, unlike NoSQLi's producer, which only ever emits already-guard-filtered
PRESERVES rows).

Property: ATTACKER_CONTROL_OF_REQUEST_HOST (see property_configs/ssrf_host.json) -- does
attacker-controlled input reach a network-request call's HOST-bearing operand (fetch/axios/
http.request/https.request/got/request) without being fixed or restricted to a value the attacker
cannot choose? Path, query, and body content are explicitly out of scope -- host control only.

containment_status, read directly from property_outcome.tsv (keyed by (sink_id, origin_id)):
  BROKEN       -- host genuinely fixed for THIS (sink, origin) alternative (a literal host
                  overwrite after attacker input, or a fixed-scheme string prefix that closes the
                  host position and leaves only the path attacker-controlled) -- NEVER emitted as
                  a finding, a genuinely resolved-safe alternative.
  OPEN         -- an on-path guard/allowlist check this producer cannot confirm actually dominates
                  the sink (v1 syntactic dominance, not confirmed), an unrecognized transform/
                  wrapper call, or a two-arg `new URL(x, base)` where x isn't statically known
                  path-relative -- emitted, needs review.
  ESTABLISHED  -- no restriction found at all -- emitted, the primary candidate shape.

SSRF-INTEG-R01-FIX01 (this session, in export_ssrf_integ.sc, not this reducer): `note` -- WHY a
given alternative was classified BROKEN/OPEN (e.g. "host overwritten by literal assignment: ...",
"guard-dominance candidate: ...", "unrecognized call: ...") -- was already computed per row but
only ever printed to the producer's own stderr; property_outcome.tsv's own two trailing columns
were always the literal placeholder "-1","-1". Confirmed by direct inspection that
adjudicate_js.py only ever reads columns 0/1/2 of this file, so the producer was fixed to write
`note` into column 3 (column 4 stays "-1", row width unchanged at 5 columns -- widening it would
silently drop every row past adjudicate_js.py's own strict len(parts)==5 filter). This reducer
reads that column back and carries it into every finding as `containment_note`, a reviewer-facing
diagnostic -- it never changes classification or containment_status itself, matching
path_traversal_verdict.py's own weak_diagnostic_guards precedent exactly (a note must never
silently promote a finding away from "not proven safe").

Source model, unlike ReDoS/Path Traversal: export_ssrf_integ.sc has no separate npm-package-own-
exported-function-parameter source family at all -- every non-WebExtension-bridged source here is
tagged `HTTP_HOST_INPUT` (req.*/message.*/Meteor.methods application-ingress boundary only). This
reducer does not invent a PACKAGE_API_INPUT-style family that the producer itself does not
compute; `origin_family` is read from source_facts.tsv column 3 and carried through verbatim,
whatever value the producer assigns (including the WebExtension bridge families, if a future
caller ever passes `browserSourceTsv` -- this reducer's own pipeline wiring does not).

Input contract:
  ssrf_verdict.py <raw_dir> <src_dir> <out.json>
    raw_dir  -- already produced by export_ssrf_integ.sc: source_facts.tsv,
                propagation_relations.tsv, property_outcome.tsv, transform_identity.tsv.
    src_dir  -- the package's own pristine source tree (adjudicate_js.py's own TCH_SRC).
    out.json -- written: {"classification": {...counts...}, "findings": [...]}.

reportable is HARDCODED False in every finding this reduces, matching every other property's own
"validate first, decide reportability later" precedent in this pipeline. Never computed by any
gate here.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adjudicate_iterative  # noqa: E402 -- ADJUDICATE-ITERATIVE-R01, see its own module
                              # docstring: drives adjudicate_js.py through every distinct
                              # unresolved alternative at a sink, not just the first one a
                              # single invocation happens to reach.
ADJUDICATOR_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/adjudicator")
PROPERTY_CONFIG = ("/home/user/bug_tracker/tchecker-research-complete/"
                    "tchecker-property-adjudicator/property_configs/ssrf_host.json")

SF_COLS = 12   # source_facts.tsv: sink_id, sink_line, src_id, origin_family, status, then 7
               # reserved-blank columns (unused by this property; adjudicate_js.py itself only
               # ever reads columns 0-4).
PR_COLS = 9    # propagation_relations.tsv: sink_id, "", "", src_id, src_line, src_code, "", "", ""
PO_COLS = 5    # property_outcome.tsv: sink_id, origin_id, outcome, note (FIX01), -1


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
    """sink_id -> list of (origin_id, origin_family, sink_line) for every row in source_facts.tsv
    -- every row here already represents a real flow the producer found (status is always
    "ESTABLISHED" in this property's own schema, meaning "reachable", not "unrestricted" -- see
    module docstring), so no status filter is needed (unlike NoSQLi's reducer, which filters on
    it because that producer's own schema uses the same column for a different purpose)."""
    rows = _read_tsv(os.path.join(raw_dir, "source_facts.tsv"), SF_COLS)
    out = {}
    for r in rows:
        sink_id, sink_line, src_id, family = r[0], r[1], r[2], r[3]
        out.setdefault(sink_id, []).append({
            "origin_id": src_id, "origin_family": family, "sink_line": sink_line,
        })
    return out


def origin_lines_and_codes(raw_dir):
    """(sink_id, origin_id) -> (line, code), read from propagation_relations.tsv directly --
    avoids a second Joern query, matching path_traversal_verdict.py's/redos_verdict.py's own
    precedent for this exact file."""
    rows = _read_tsv(os.path.join(raw_dir, "propagation_relations.tsv"), PR_COLS)
    out = {}
    for r in rows:
        out[(r[0], r[3])] = (r[4], r[5])
    return out


def containment_status_and_note(raw_dir):
    """(sink_id, origin_id) -> (outcome, note), read directly from property_outcome.tsv --
    per-alternative, not a single sink-level summary. `note` is column 3, added by
    SSRF-INTEG-R01-FIX01 -- absent (empty string) on any raw dir produced before that fix, which
    this reducer treats as simply "no diagnostic available," never an error."""
    rows = _read_tsv(os.path.join(raw_dir, "property_outcome.tsv"), PO_COLS)
    out = {}
    for r in rows:
        out[(r[0], r[1])] = (r[2], r[3])
    return out


def run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir):
    if os.path.isdir(out_dir):
        for fn in os.listdir(out_dir):
            os.remove(os.path.join(out_dir, fn))
    os.makedirs(out_dir, exist_ok=True)
    # ask_fn=None: still asks only the FIRST unresolved alternative, still never fabricates an
    # answer -- the returned evidence carries a real, honest `_adjudication_loop.
    # unaddressed_alternative_count`, matching every other reducer's own use of this driver.
    return adjudicate_iterative.run_adjudicate_sink_iterative(
        ADJUDICATOR_DIR, raw_dir, src_dir, out_dir, PROPERTY_CONFIG,
        sink=sink_id, finding_file="ssrf_candidate.js", ask_fn=None)


def emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=True):
    alts = alternatives_by_sink(raw_dir)
    lines_codes = origin_lines_and_codes(raw_dir)
    outcomes = containment_status_and_note(raw_dir)

    classification = {
        "SINKS_WITH_HOST_BEARING_FLOW": len(alts),
        "ALTERNATIVES_BROKEN_EXCLUDED": 0,   # genuinely proven host-fixed -- never a finding
        "ALTERNATIVES_ESTABLISHED": 0,
        "ALTERNATIVES_OPEN": 0,
        "ADJUDICATOR_RUN_FAILED": 0,
    }
    findings = []
    for sink_id in sorted(alts):
        alternatives = alts[sink_id]
        evidence = None
        adjudicator_error = None
        if run_adjudicator:
            out_dir = os.path.join(work_dir, f"adj_{sink_id}")
            evidence, adjudicator_error = run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir)
            if evidence is None:
                classification["ADJUDICATOR_RUN_FAILED"] += 1

        for alt in alternatives:
            key = (sink_id, alt["origin_id"])
            outcome, note = outcomes.get(key, ("ESTABLISHED", ""))
            if outcome == "BROKEN":
                classification["ALTERNATIVES_BROKEN_EXCLUDED"] += 1
                continue  # genuinely proven host-fixed -- never surfaced as a finding
            classification["ALTERNATIVES_ESTABLISHED" if outcome == "ESTABLISHED" else "ALTERNATIVES_OPEN"] += 1
            line, code = lines_codes.get(key, (alt["sink_line"], ""))
            findings.append({
                "property": "SSRF",
                "sink_node_id": sink_id,
                "sink_line": int(alt["sink_line"]) if str(alt["sink_line"]).lstrip("-").isdigit() else -1,
                "origin_node_id": alt["origin_id"],
                "origin_line": int(line) if str(line).lstrip("-").isdigit() else -1,
                "origin_code": code,
                "origin_family": alt["origin_family"],
                "classification": "ATTACKER_CONTROL_OF_REQUEST_HOST_CANDIDATE",
                "containment_status": outcome,
                "containment_note": note,
                "adjudicator_disposition": evidence.get("disposition") if evidence else None,
                "adjudicator_property_outcome": evidence.get("property_outcome") if evidence else None,
                "adjudicator_status": "OK" if evidence else ("RUN_FAILED" if run_adjudicator else "SKIPPED"),
                "adjudicator_error": (adjudicator_error or "")[-2000:] if adjudicator_error else None,
                "unaddressed_alternative_count":
                    (evidence.get("_adjudication_loop", {}).get("unaddressed_alternative_count")
                     if evidence else None),
                "reportable": False,
            })
    return classification, findings


def main():
    if len(sys.argv) != 4:
        print("usage: ssrf_verdict.py <raw_dir> <src_dir> <out.json>", file=sys.stderr)
        sys.exit(2)
    raw_dir, src_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    work_dir = out_path + ".work"
    os.makedirs(work_dir, exist_ok=True)
    run_adjudicator = os.environ.get("SSRF_VERDICT_SKIP_ADJUDICATOR") != "1"
    classification, findings = emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=run_adjudicator)
    with open(out_path, "w") as f:
        json.dump({"classification": classification, "findings": findings}, f, indent=2)
    print(json.dumps({"classification": classification, "n_findings": len(findings)}, indent=2))


if __name__ == "__main__":
    main()
