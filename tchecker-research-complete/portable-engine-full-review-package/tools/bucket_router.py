#!/usr/bin/env python3
"""Automatic uncertainty-bucket + route layer for TChecker.

This is the piece the thesis's A/B/C experiment REQUIRES and that was missing:
the bucket, unresolved property, and recommended route must be emitted BY THE
SCANNER from its own candidate signals, NOT hand-written by a person preparing
the experiment. If a human reads a case, decides why TChecker is uncertain, and
writes the category into Condition C, the experiment tests whether a human hint
helps the LLM -- not whether TChecker's bucket method works. This module removes
the human from that step.

Input: the candidate dicts the frozen producers already emit (no change to their
verdict logic). Output, per candidate, the record the prompt generator consumes:

    {
      "candidate_id":        <stable fingerprint from frozen scanner + candidate>,
      "established_facts":    [ ... derived from the candidate's own fields ... ],
      "unresolved_property":  <what specifically could not be proven>,
      "uncertainty_bucket":   <derived from the candidate's structural signals>,
      "recommended_route":    <derived from the bucket>
    }

DERIVATION IS PURELY FROM SCANNER-OBSERVABLE SIGNALS:
- Any producer that EMITTED a candidate has, by this family's abstain-never-
  VULNERABLE posture, failed to PROVE safety for a specific relationship. That is
  a `relationship_unresolved` uncertainty by construction, routed to
  `llm_semantic_review`.
- The specific `unresolved_property` is keyed off the candidate's SUBCLASS (the
  kind of relationship that producer reasons about), which is a scanner output,
  not a human judgement:
    * a width-vs-capacity producer (has a `width_expr`: RUNTIME_CAPACITY,
      INTERPROCEDURAL, CALL_SINK, COPY_LENGTH) -> the write LENGTH bound is
      unresolved.
    * a cursor/pointer-increment producer (count-based, `write_shape`/`pointer`)
      -> the write COUNT bound is unresolved.
    * an indexed-store producer (INDEX_STORE) -> the INDEX bound is unresolved.

The focused question shown in Condition C is rendered by a FIXED TEMPLATE keyed
on `unresolved_property` (see PROPERTY_RENDER) -- also not a per-case human hint.
A generic, property-templated question is deliberately preferred over a
case-specific one precisely because a case-specific question would smuggle human
insight into the condition under test.

NO-CANDIDATE cases (producer_evidence_missing, analysis_capability_missing) are
NOT handled here: there is no candidate to route, so there is nothing for the
A/B/C experiment to consume. Those remain in the separate routing evaluation and
are, honestly, not yet auto-classified end-to-end (that needs producers to log
WHY they emitted nothing -- an absent fact vs an unmodeled shape -- which they do
not yet do). This module covers exactly the candidate-bearing, LLM-routable set
the A/B/C experiment needs.
"""
import hashlib
import importlib
import json
import sys

# Frozen producer registry. Each name maps to a module exposing emit_candidates(prefix).
PRODUCERS = (
    "oob_runtime_capacity_verdict",
    "oob_interprocedural_verdict",
    "oob_call_sink_verdict",
    "oob_copy_length_verdict",
    "oob_cursor_write_verdict",
    "oob_pointer_increment_verdict",
    "oob_index_write_verdict",
)

# unresolved_property -> (category label shown in C, focused-question template).
# Templates are generic and property-keyed on purpose: no per-case human phrasing.
PROPERTY_RENDER = {
    "write_length_within_capacity": (
        "relationship unresolved",
        "Does the code guarantee that the number of bytes written by the "
        "highlighted operation is no greater than the destination buffer's "
        "allocated capacity?",
    ),
    "write_count_within_capacity": (
        "relationship unresolved",
        "Does the code bound the number of writes made through this pointer to "
        "no more than the destination buffer's capacity?",
    ),
    "index_within_bounds": (
        "relationship unresolved",
        "Does the code guarantee that the index used by the highlighted "
        "operation stays within the array's bounds?",
    ),
}


def _stable_id(cand):
    """Fingerprint reproducible from the frozen scanner artifact + candidate.
    Deliberately excludes volatile numeric node ids; uses file/function/subclass/
    line + the destination or base identifier."""
    dest = cand.get("dest") or cand.get("base") or cand.get("array") or ""
    key = "|".join(str(x) for x in (
        cand.get("file"), cand.get("function"), cand.get("subclass"),
        cand.get("line"), dest))
    return "cand_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _derive_property(cand):
    """unresolved_property from the candidate's SUBCLASS (a scanner output)."""
    sub = cand.get("subclass")
    if sub in ("CURSOR", "POINTER_INCREMENT"):
        return "write_count_within_capacity"
    if sub in ("INDEX_STORE",):
        return "index_within_bounds"
    # width-vs-capacity families (RUNTIME_CAPACITY, INTERPROCEDURAL, CALL_SINK,
    # COPY_LENGTH) -- anything carrying a write-width expression.
    if cand.get("width_expr") is not None:
        return "write_length_within_capacity"
    # fallback: any other emitted candidate is still a length-bound relationship
    return "write_length_within_capacity"


def _readable_provenance(prov):
    """Render a provenance string without internal numeric node ids.
    e.g. 'alias_of:107374182407:block' -> 'inherited via alias of block';
         'offset_from:..:q' -> 'derived by offset from q'; 'direct_allocation'
    stays as-is."""
    parts = prov.split(":")
    kind = parts[0]
    tail = parts[-1] if len(parts) > 1 else None
    if kind == "alias_of" and tail:
        return f"inherited via alias of {tail}"
    if kind.startswith("offset") and tail:
        return f"derived by pointer offset from {tail}"
    if kind == "direct_allocation":
        return "from a direct allocation in this function"
    if kind.startswith("propagated") and tail:
        return f"propagated across a call from {tail}"
    return kind.replace("_", " ")


def _established_facts(cand):
    """Facts drawn ONLY from the candidate's own fields -- no human narration."""
    facts = []
    dest = cand.get("dest") or cand.get("base") or cand.get("array")
    if dest:
        facts.append(f"destination: {dest}")
    if cand.get("extent_in_bytes") is not None:
        facts.append(f"destination capacity: {cand['extent_in_bytes']} bytes (resolved)")
    elif cand.get("elem_count") is not None:
        facts.append(f"destination capacity: {cand['elem_count']} bytes (resolved)")
    elif cand.get("size_expression") is not None:
        facts.append(f"destination capacity: {cand['size_expression']} (symbolic, not a literal)")
    if cand.get("width_expr") is not None:
        facts.append(f"write length: {cand['width_expr']}")
    if cand.get("write_shape"):
        facts.append(f"write shape: {cand['write_shape']} through pointer {cand.get('pointer')}")
    prov = cand.get("provenance")
    if prov:
        facts.append(f"capacity provenance: {_readable_provenance(prov)}")
    if cand.get("callee"):
        facts.append(f"write performed by: {cand['callee']} "
                     f"(contract: {cand.get('contract_source')})")
    facts.append(f"located at {cand.get('file')}:{cand.get('line')} in {cand.get('function')}")
    return facts


def derive_record(cand):
    """The automatic bucket record for one emitted candidate."""
    prop = _derive_property(cand)
    return {
        "candidate_id": _stable_id(cand),
        "subclass": cand.get("subclass"),
        "file": cand.get("file"),
        "function": cand.get("function"),
        "line": cand.get("line"),
        "established_facts": _established_facts(cand),
        "unresolved_property": prop,
        "uncertainty_bucket": "relationship_unresolved",
        "recommended_route": "llm_semantic_review",
    }


def route_factfile(prefix, producers=PRODUCERS):
    """Run the frozen producers on a fact file and auto-emit a bucket record for
    every candidate. Returns a list of records."""
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    records = []
    for name in producers:
        try:
            mod = importlib.import_module(name)
        except Exception:
            continue
        for cand in mod.emit_candidates(prefix):
            records.append(derive_record(cand))
    return records


def render_for_condition_c(record):
    """The category + focused question Condition C shows, rendered by fixed
    template from the AUTO-emitted unresolved_property -- not a human hint."""
    category, question = PROPERTY_RENDER[record["unresolved_property"]]
    return {"uncertainty_category": category, "focused_question": question}


if __name__ == "__main__":
    for prefix in sys.argv[1:]:
        recs = route_factfile(prefix)
        print(f"== {prefix}: {len(recs)} auto-bucketed candidate(s) ==")
        for r in recs:
            print(json.dumps(r, indent=2))
