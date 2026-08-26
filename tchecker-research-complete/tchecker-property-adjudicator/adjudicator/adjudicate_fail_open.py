#!/usr/bin/env python3
"""Stage FAIL_OPEN_SECURITY_CONTROL candidates at the existing semantic-hint boundary.

The Joern producer establishes only a candidate shape. This adapter never upgrades that shape to
a vulnerability or to established dataflow. It emits the same compact LLM packet schema and the
same SAFE | UNSAFE | UNKNOWN advisory-hint contract used by the property adjudicator.
"""
import argparse
import json
from pathlib import Path

COLUMNS = (
    "candidate_id", "file", "line", "then_call_id", "fulfilled_handler_id",
    "fulfilled_handler_code", "rejected_handler_id", "rejected_handler_code",
    "enclosing_method", "enclosing_method_full_name", "then_expression", "method_code",
    "handler_definition_id", "handler_definition_full_name", "handler_definition_body",
    "handler_definition_status",
    "candidate_class", "deterministic_status",
)
VALUES = {"SAFE", "UNSAFE", "UNKNOWN"}
CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


def load_rows(raw_dir: Path):
    path = raw_dir / "fail_open_candidates.tsv"
    if not path.exists():
        raise FileNotFoundError(f"required candidate fact file is missing: {path}")
    result = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != len(COLUMNS):
            raise ValueError(f"{path}:{number}: expected {len(COLUMNS)} columns, got {len(fields)}")
        row = dict(zip(COLUMNS, fields))
        if row["candidate_class"] != "FAIL_OPEN_SECURITY_CONTROL":
            raise ValueError(f"{path}:{number}: unexpected candidate class {row['candidate_class']!r}")
        if row["deterministic_status"] != "UNKNOWN":
            raise ValueError(f"{path}:{number}: fail-open candidate must remain UNKNOWN")
        result.append(row)
    return result


def load_hints(path):
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("hint file must be an object keyed by property_id")
    for prop, hint in data.items():
        if hint.get("proposed_value") not in VALUES:
            raise ValueError(f"{prop}: proposed_value must be SAFE, UNSAFE, or UNKNOWN")
        if hint.get("confidence") not in CONFIDENCE:
            raise ValueError(f"{prop}: confidence must be LOW, MEDIUM, or HIGH")
        if not isinstance(hint.get("rationale"), str) or not hint["rationale"].strip():
            raise ValueError(f"{prop}: non-empty rationale is required")
    return data


def property_id(row):
    return f"{row['candidate_id']}.fails_closed_on_dependency_error"


def disposition(hint):
    if hint is None or hint["proposed_value"] == "UNKNOWN" or hint["confidence"] != "HIGH":
        return "CANDIDATE_OPEN", "NEEDS_MORE_REVIEW" if hint else None
    if hint["proposed_value"] == "SAFE":
        return "RESOLVED_SAFE_BY_ACCEPTED_HINT", "ACCEPTED_HINT"
    return "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT", "ACCEPTED_HINT"


def packet(row, prior):
    prop = property_id(row)
    rejected = row["rejected_handler_code"]
    method = row["enclosing_method"]
    question = (
        f"Static analysis found the same handler syntax (`{rejected}`) in both the fulfillment "
        f"and rejection positions of this Promise.then call inside `{method}`. The surrounding "
        "method has bounded security-decision indicators, but this is only a candidate shape. "
        "Based ONLY on the supplied code, does the rejection continuation fail closed so a "
        "dependency error cannot make the security decision more permissive? Return SAFE only "
        "when the error path blocks, rejects, rethrows, or otherwise cannot grant/bypass the "
        "control; return UNSAFE when the error path can yield a permissive default that reaches "
        "the decision; return UNKNOWN when the evidence is insufficient. Do not infer semantics "
        "from handler or method names."
    )
    return {
        "schema": "tchecker-llm-packet/1.0",
        "round": 1,
        "finding_id": f"fail-open-security-control:{row['file']}#then{row['then_call_id']}",
        "property_id": prop,
        "candidate_class": "FAIL_OPEN_SECURITY_CONTROL",
        "deterministic_status": "UNKNOWN",
        "candidate_evidence": {
            "established_shape": "SYNTACTICALLY_IDENTICAL_FULFILLMENT_AND_REJECTION_HANDLERS",
            "handler_identity_status": row["handler_definition_status"],
            "security_context_status": "HEURISTIC",
            "limitation": "No vulnerability, permissive default, or developer intent is established by this shape.",
        },
        "alternative": {
            "origin": {
                "origin_family": "EXTERNAL_DEPENDENCY_REJECTION",
                "source_node_id": row["rejected_handler_id"],
                "source_code": rejected,
                "source_line": int(row["line"]),
                "source_containing_statement": row["then_expression"],
                "source_containing_function": row["enclosing_method_full_name"],
                "established_by": "EXACT_CALL_ARGUMENT_POSITION",
            },
            "steps": [{
                "path_order": 0,
                "node_id": row["rejected_handler_id"],
                "node_kind": "REJECTION_CONTINUATION",
                "callee_name": rejected,
                "path_membership": "CANDIDATE_SHAPE",
                "callsite_code": rejected,
                "containing_statement": row["then_expression"],
                "containing_function": row["enclosing_method_full_name"],
                "definition_status": "UNKNOWN",
                "definition_identity": row["handler_definition_full_name"] or None,
                "definition_status": row["handler_definition_status"],
                "definition_body": row["handler_definition_body"] or None,
            }],
            "sink": {
                "node_id": row["then_call_id"],
                "line": int(row["line"]),
                "kind": "Promise.then",
                "sink_model": "SECURITY_DECISION_ON_DEPENDENCY_RESULT",
                "class": "fail-open-security-control",
                "downstream_primitive": "enclosing security decision",
                "expression": row["then_expression"],
                "containing_statement": row["method_code"],
                "containing_function": row["enclosing_method_full_name"],
            },
            "qualification": "CANDIDATE_SHAPE",
            "necessity": "UNKNOWN",
        },
        "PRIOR_SEMANTIC_HINTS_ADVISORY": prior,
        "unresolved_subject": {
            "node_id": row["rejected_handler_id"],
            "node_kind": "REJECTION_CONTINUATION",
            "deterministic_status": "UNKNOWN",
        },
        "QUESTION": question,
        "answer_contract": {
            "proposed_value": "SAFE | UNSAFE | UNKNOWN",
            "confidence": "LOW | MEDIUM | HIGH",
            "source_must_be": "LLM",
            "rationale": "string",
            "value_meanings": {
                "SAFE": "the supplied rejection path fails closed",
                "UNSAFE": "the supplied rejection path can make the control more permissive",
                "UNKNOWN": "the supplied evidence is insufficient",
            },
            "note": "This is a semantic HINT over a heuristic candidate, not a fact.",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--hints", type=Path)
    args = parser.parse_args()
    rows = load_rows(args.raw_dir)
    hints = load_hints(args.hints)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    evidence = []
    prior = []
    for index, row in enumerate(rows, 1):
        prop = property_id(row)
        hint = hints.get(prop)
        disp, use = disposition(hint)
        evidence.append({
            "finding_id": f"fail-open-security-control:{row['file']}#then{row['then_call_id']}",
            "property_id": prop,
            "candidate_class": row["candidate_class"],
            "deterministic_status": "UNKNOWN",
            "semantic_hint": hint,
            "adjudication_use": use,
            "disposition": disp,
        })
        if hint is None or use != "ACCEPTED_HINT":
            (args.out_dir / f"llm_input_{index}.json").write_text(
                json.dumps(packet(row, prior), indent=2) + "\n", encoding="utf-8")
        if hint:
            prior.append({"property_id": prop, **hint, "source": "LLM", "status": "advisory"})
    (args.out_dir / "evidence_v0.json").write_text(json.dumps({
        "schema": "fail-open-candidate-evidence/1.0",
        "candidate_count": len(evidence),
        "candidates": evidence,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"FAIL_OPEN_ADJUDICATION={len(evidence)} candidates; packets={sum(1 for e in evidence if e['adjudication_use'] != 'ACCEPTED_HINT')}")


if __name__ == "__main__":
    main()
