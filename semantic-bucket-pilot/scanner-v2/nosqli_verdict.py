#!/usr/bin/env python3
"""NOSQLI-REDUCE-R01: reduces export_nosqli_integ.sc's own real raw facts (plus, for each
candidate sink, a real adjudicate_js.py run against property_configs/nosqli_query_op.json --
unchanged, read-only) into the standard {classification, findings} shape every other npm-pipeline
scanner emits, matching redos_verdict.py's/path_traversal_verdict.py's own structural model (same
`<raw_dir> <src_dir> <out.json>` CLI contract).

Property: ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE (see property_configs/nosqli_query_op.json)
-- does attacker-controlled input reach a MongoDB query selector FIELD without being constrained to
a primitive (non-object) type, enabling operator injection ($ne, $regex, $gt, $where)?

Unlike ReDoS/Path Traversal, this property's own producer (export_nosqli_integ.sc) already performs
ALL guard/coercion/API-schema-gate classification itself, in Scala, before a row is ever written --
a row in source_facts.tsv is, by construction, already an unguarded, non-coerced, non-API-gated
PRESERVES target with a real ESTABLISHED source alternative (see that file's own `preservesTargets`
filter). So there is no separate containment_status tier to compute here the way path_traversal_
verdict.py computes BROKEN/OPEN/ESTABLISHED from property_outcome.tsv -- property_outcome.tsv exists
for this property but every row in it reads ESTABLISHED unconditionally (confirmed by direct
inspection of the producer: `po.println(Seq(sinkId, srcId, "ESTABLISHED", "-1", "-1")...)`), so this
reducer does not read it at all; reading it would add nothing over source_facts.tsv's own presence.

Per-field granularity, NOSQLI-INTEG-R01-FIX01: a single query call can carry multiple DISTINCT
fields in its selector (`findOne({ email, statusFlag })` is two separate targets, per Stage 1's own
per-operand discipline -- see NOSQLI_SINK_SEMANTICS_MATRIX.md). The producer's sinkId is the CALL's
own node ID, shared by every field at that call; before FIX01, field identity (fieldKind/fieldName/
value-operand code -- already computed per-target, only ever printed to the producer's own stderr)
was never written to source_facts.tsv, so two distinct-field rows at the same call were
indistinguishable to any reducer. Confirmed as a real, structural (not hypothetical) gap by
constructing a two-distinct-field fixture and observing the identical sinkId with no way to tell
which row was which field, before fixing the producer to persist columns 5/6/7 (field_kind,
field_name, value_code -- previously always blank, adjudicate_js.py itself never reads past column
4). This reducer reads those three columns directly rather than working around their absence.

Known, disclosed limitation NOT fixed in this pass (same "flag it, don't silently work around it"
discipline as every other producer gap found this session): API-route AJV/JSON-schema-gated targets
and nested-object-literal-value targets are excluded by the producer (correctly -- see
NOSQLI_STAGE3_RESULT_AND_AJV_GAP.md/NOSQLI_SCANNER_FIXES.md, "detected-but-unresolved gate reported
as an explicit exclusion category, never silently folded into PRESERVES"), but that exclusion count
currently exists ONLY in the producer's own stderr log (`excluded N targets behind a detected API
route ... schema gate`), not in any persisted TSV a reducer can read back -- unlike Path Traversal's
sink_abstentions.tsv (PATH-TRAV-REDUCE-R02). This does not create false positives (a gated target
never reaches source_facts.tsv at all), only a completeness gap in the CLASSIFICATION summary: this
reducer cannot currently report "N targets were excluded here because of a detected but unresolved
schema gate" the way path_traversal_verdict.py reports its abstentions. Worth a follow-up producer
change (persist those exclusions to their own TSV, mirroring sink_abstentions.tsv) if/when this
property is scaled past validation -- deliberately not done here, matching this pass's scope.

reportable is HARDCODED False in every finding this reduces, matching every other property's own
"validate first, decide reportability later" precedent in this pipeline. Never computed by any gate
here.
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
                    "tchecker-property-adjudicator/property_configs/nosqli_query_op.json")

SF_COLS = 12   # source_facts.tsv: sink_id, sink_line, src_id, origin_family, status, field_kind,
               # field_name, value_code, then 4 reserved-blank columns (NOSQLI-INTEG-R01-FIX01
               # added columns 5/6/7; adjudicate_js.py itself only ever reads columns 0-4).
PR_COLS = 9    # propagation_relations.tsv: sink_id, "", "", src_id, src_line, src_code, "", "", ""


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


def candidates_by_sink(raw_dir):
    """sink_id -> list of (origin_id, sink_line, field_kind, field_name, value_code) for every
    ESTABLISHED (already-guard-filtered, source-reachable) row -- one entry per distinct field at
    that sink, not deduplicated to the sink's first row (see module docstring, FIX01)."""
    rows = _read_tsv(os.path.join(raw_dir, "source_facts.tsv"), SF_COLS)
    out = {}
    for r in rows:
        sink_id, sink_line, src_id, status = r[0], r[1], r[2], r[4]
        field_kind, field_name, value_code = r[5], r[6], r[7]
        if status != "ESTABLISHED":
            continue
        out.setdefault(sink_id, []).append({
            "origin_id": src_id, "sink_line": sink_line,
            "field_kind": field_kind, "field_name": field_name, "value_code": value_code,
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
        sink=sink_id, finding_file="nosqli_candidate.js", ask_fn=None)


def emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=True):
    cands = candidates_by_sink(raw_dir)
    lines_codes = origin_lines_and_codes(raw_dir)

    classification = {
        "SINKS_WITH_CANDIDATE_FIELD": len(cands),
        "CANDIDATE_FIELD_ROWS": sum(len(v) for v in cands.values()),
        "ADJUDICATOR_RUN_FAILED": 0,
    }
    findings = []
    for sink_id in sorted(cands):
        rows = cands[sink_id]
        evidence = None
        adjudicator_error = None
        if run_adjudicator:
            out_dir = os.path.join(work_dir, f"adj_{sink_id}")
            evidence, adjudicator_error = run_adjudicate_one_sink(raw_dir, src_dir, sink_id, out_dir)
            if evidence is None:
                classification["ADJUDICATOR_RUN_FAILED"] += 1

        for row in rows:
            key = (sink_id, row["origin_id"])
            line, code = lines_codes.get(key, (row["sink_line"], ""))
            findings.append({
                "property": "NOSQLI",
                "sink_node_id": sink_id,
                "sink_line": int(row["sink_line"]) if str(row["sink_line"]).lstrip("-").isdigit() else -1,
                "field_kind": row["field_kind"],
                "field_name": row["field_name"],
                "value_code": row["value_code"],
                "origin_node_id": row["origin_id"],
                "origin_line": int(line) if str(line).lstrip("-").isdigit() else -1,
                "origin_code": code,
                "classification": "ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE_CANDIDATE",
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
        print("usage: nosqli_verdict.py <raw_dir> <src_dir> <out.json>", file=sys.stderr)
        sys.exit(2)
    raw_dir, src_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    work_dir = out_path + ".work"
    os.makedirs(work_dir, exist_ok=True)
    run_adjudicator = os.environ.get("NOSQLI_VERDICT_SKIP_ADJUDICATOR") != "1"
    classification, findings = emit_findings(raw_dir, src_dir, work_dir, run_adjudicator=run_adjudicator)
    with open(out_path, "w") as f:
        json.dump({"classification": classification, "findings": findings}, f, indent=2)
    print(json.dumps({"classification": classification, "n_findings": len(findings)}, indent=2))


if __name__ == "__main__":
    main()
