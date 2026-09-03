#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- reachability layer (language-neutral).

Sits on top of the frozen parser layer. The parser layer decides whether a quote-boundary
rule can establish escape-run parity; this layer decides whether such a parser sits on a
proven second-order path:

    stored file / archive / dump / database row
         -> the quoted-value parser
         -> decode / replace / re-encode
         -> a structured-data interpreter or database import routine

The two classifications:

  ESCAPE_PARITY_PARSER_CANDIDATE              a structurally incomplete boundary rule,
                                              and nothing else is required
  DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE  the above PLUS a proven chain, with every
                                              identity on it resolved and unambiguous

Every edge is real dataflow computed by the engine. Abstention is mandatory, never
optional, when a delayed-source identity, a parser linkage, a transformation identity or
a downstream-consumer identity is unresolved or ambiguous: the site then stays a
CANDIDATE and the chain records why it could not be established.

EXECUTION TIMING (scheduled, deferred, administrative) is carried as evidence only. It
never promotes and never demotes a verdict.

A chain that fails to establish records the SEARCH SPACE it failed within: how many
modelled sources and structured consumers existed in the analysed unit at all. A unit
containing none of them cannot produce a traced negative, only a vacuous one, and the
reason strings keep those apart -- NO_SOURCE_API_MODELLED_IN_UNIT and
NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT say the model does not cover this codebase,
where NO_DELAYED_SOURCE_REACHES_PARSER and NO_STRUCTURED_TEXT_CONSUMER_REACHED say
flows were computed and did not connect.

Both languages use this one reducer, over the same fact schema.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from escape_parity_sites import derive as derive_sites, _rows, CANDIDATE, NEGATIVE, ABSTAINED  # noqa: E402

REACHABLE = "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"

# A negative that could never have come out any other way is not a finding
# about the code -- it is a finding about the model's coverage of the code. The
# two must not share a reason string.
NO_SOURCE_MODELLED = "NO_SOURCE_API_MODELLED_IN_UNIT"
NO_CONSUMER_MODELLED = "NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT"

BLOCKING = ("UNRESOLVED_SOURCE_IDENTITY", "AMBIGUOUS_LOCAL_DEFINITION",
            "AMBIGUOUS_PARSER_LINKAGE", "UNRESOLVED_CONSUMER_IDENTITY",
            "AMBIGUOUS_CONSUMER_LINKAGE", "UNRESOLVED_CALLBACK_IDENTITY")


def derive(raw_dir, language=None):
    raw = Path(raw_dir)
    result = derive_sites(raw_dir, language)

    sources, src_abstentions = {}, []
    for f_, meth, line, nid, ident, res, kind in _rows(raw / "delayed_sources.tsv", 7):
        rec = {"node_id": nid, "api_identity": ident, "resolution": res,
               "source_kind": kind, "file": f_, "line": line}
        if res.startswith("RESOLVED"):
            sources[nid] = rec
        else:
            src_abstentions.append(rec)

    transforms = {}
    for f_, meth, line, nid, fam, ident, res in _rows(raw / "transform_calls.tsv", 7):
        transforms[nid] = {"node_id": nid, "family": fam, "callee_identity": ident,
                           "resolution": res, "line": line}

    consumers, logging_only, con_abstentions = {}, {}, []
    for f_, meth, line, nid, ident, kind, res in _rows(raw / "consumers.tsv", 7):
        rec = {"node_id": nid, "consumer_identity": ident, "kind": kind,
               "resolution": res, "file": f_, "line": line}
        if not res.startswith("RESOLVED"):
            con_abstentions.append(rec)
        elif kind == "LOGGING_ONLY":
            logging_only[nid] = rec
        else:
            consumers[nid] = rec

    # parser method id -> its call sites (with linkage resolution)
    # anchors are keyed by the boundary-rule SITE id (a regex node) or by the parser
    # METHOD id (a hand-written scanner); a finding matches on either.
    anchors, anchor_abstain = {}, {}
    for f_, pmeth, key, kind, cid, line, res in _rows(raw / "parser_anchors.tsv", 7):
        if res.startswith("RESOLVED"):
            anchors.setdefault(key, []).append(
                {"call_node_id": cid, "line": line, "anchor_kind": kind})
        else:
            anchor_abstain.setdefault(key, []).append(res)

    edges = {}
    for fk, fid, tk, tid, kind in _rows(raw / "chain_edges.tsv", 5):
        edges.setdefault(kind, {}).setdefault(tid, set()).add(fid)

    timing_by_method = {}
    for f_, meth, line, nid, kind in _rows(raw / "execution_timing.tsv", 5):
        timing_by_method.setdefault(meth, []).append(
            {"kind": kind, "node_id": nid, "line": line, "in_method": meth})

    # the method a parser is CALLED from is part of the chain, so timing evidence there
    # is attached to the finding too -- still as evidence only, never as a guard.
    caller_of_call = {}
    for f_, meth, line, nid, kind in _rows(raw / "execution_timing.tsv", 5):
        pass
    anchor_caller = {}
    for f_, pmeth, pmid, cid, line, res in _rows(raw / "parser_anchors.tsv", 6):
        anchor_caller.setdefault(pmid, set())
    call_method = {}
    for f_, meth, line, nid, fam, ident, res in _rows(raw / "transform_calls.tsv", 7):
        call_method[nid] = meth
    for f_, meth, line, nid, ident, res, kind in _rows(raw / "delayed_sources.tsv", 7):
        call_method[nid] = meth

    def sources_into(kind, target):
        return edges.get(kind, {}).get(target, set())

    def targets_from(kind, origin):
        return {t for t, fs in edges.get(kind, {}).items() if origin in fs}

    # a consumer fed by more than one distinct parser cannot be attributed
    ambiguous_consumers = set()
    for cid in consumers:
        feeders = sources_into("PARSER2CONSUMER", cid)
        for enc in sources_into("ENCODE2CONSUMER", cid):
            feeders |= sources_into("PARSER2ENCODE", enc)
        if len({f for f in feeders}) > 1:
            ambiguous_consumers.add(cid)

    for rec in result["findings"]:
        chain = {"status": "NOT_ESTABLISHED", "reasons": [], "parser_calls": [],
                 "delayed_sources": [], "transforms": [], "consumers": [],
                 "logging_only_consumers": []}
        # timing in the parser's own method, plus timing in any method a delayed source
        # on this chain lives in (the scheduled/administrative entry point)
        timing = list(timing_by_method.get(rec.get("method", ""), []))
        rec["chain"] = chain

        rec["execution_timing_evidence"] = timing
        if rec["classification"] not in (CANDIDATE,):
            chain["reasons"].append("NOT_A_CANDIDATE_NO_CHAIN_REQUIRED")
            continue

        mid = rec.get("method_node_id")
        sid = rec.get("site_node_id")
        calls = anchors.get(sid, []) + anchors.get(mid, [])
        chain["parser_calls"] = calls
        for k in (sid, mid):
            if k in anchor_abstain and not calls:
                chain["reasons"].extend(sorted(set(anchor_abstain[k])))
        if not calls:
            chain["reasons"].append("PARSER_NEVER_CALLED_IN_ANALYSED_SOURCE")

        for call in calls:
            cid = call["call_node_id"]
            # a replace-anchored parser whose replacement callback never resolved cannot
            # have its transformation identity established
            t = transforms.get(cid)
            if t is not None:
                chain["transforms"].append(t)
                if not t["resolution"].startswith("RESOLVED"):
                    chain["reasons"].append(t["resolution"])
            for s in sources_into("DELAYED_SOURCE2PARSER", cid):
                if s in sources:
                    chain["delayed_sources"].append(sources[s])
            encs = targets_from("PARSER2ENCODE", cid)
            for e in encs:
                if e in transforms:
                    chain["transforms"].append(transforms[e])
            cons = set(targets_from("PARSER2CONSUMER", cid))
            for e in encs:
                cons |= targets_from("ENCODE2CONSUMER", e)
            for c in cons:
                if c in consumers:
                    chain["consumers"].append(consumers[c])
                    if c in ambiguous_consumers:
                        chain["reasons"].append("AMBIGUOUS_CONSUMER_LINKAGE")
                elif c in logging_only:
                    chain["logging_only_consumers"].append(logging_only[c])
            for c in targets_from("PARSER2LOGGING", cid):
                if c in logging_only:
                    chain["logging_only_consumers"].append(logging_only[c])

        for s_ in chain["delayed_sources"]:
            for t in timing_by_method.get(call_method.get(s_["node_id"], ""), []):
                if t not in timing:
                    timing.append(t)
        rec["execution_timing_evidence"] = timing

        # What was actually available to search. Without this a reader cannot tell
        # a traced negative from a vacuous one, and the two look identical.
        chain["search_space"] = {
            "resolved_sources_in_unit": len(sources),
            "unresolved_sources_in_unit": len(src_abstentions),
            "structured_consumers_in_unit": len(consumers),
            "logging_only_consumers_in_unit": len(logging_only),
            "parser_call_sites": len(calls),
            "flow_edges_in_unit": sum(len(v) for kind in edges.values()
                                      for v in kind.values()),
            # Per-segment edge counts let a reader independently verify which
            # segments of the full source->parser->consumer path were queried
            # and whether each returned empty or non-empty.  The aggregate
            # flow_edges_in_unit alone cannot distinguish a unit where
            # DELAYED_SOURCE2PARSER ran and found nothing from one where
            # DELAYED_SOURCE2PARSER was never even attempted.
            "flow_edges_by_kind": {k: sum(len(v) for v in d.values())
                                   for k, d in edges.items()},
        }

        if not calls:
            # With no call site there is nothing to trace from, so neither of the
            # reasons below would mean anything. PARSER_NEVER_CALLED_IN_ANALYSED_
            # SOURCE, already recorded above, is the whole story.
            pass
        else:
            if not chain["delayed_sources"]:
                chain["reasons"].append(
                    NO_SOURCE_MODELLED if not sources
                    else "NO_DELAYED_SOURCE_REACHES_PARSER")
            if not chain["consumers"]:
                chain["reasons"].append(
                    NO_CONSUMER_MODELLED if not consumers
                    else "NO_STRUCTURED_TEXT_CONSUMER_REACHED")

        blocking = [r for r in chain["reasons"] if r in BLOCKING]
        if chain["delayed_sources"] and chain["consumers"] and not blocking:
            chain["status"] = "ESTABLISHED"
            rec["classification"] = REACHABLE
        elif blocking:
            chain["status"] = "ABSTAINED"
            rec["chain_abstention_reason"] = sorted(set(blocking))
        chain["reasons"] = sorted(set(chain["reasons"]))

    result["schema"] = "escape-parity-boundary/chain-0.1"
    result["classification_vocabulary"] = [CANDIDATE, REACHABLE]
    result["chain_note"] = (
        "The reachability layer promotes a candidate only when a delayed source reaches "
        "the parser AND the parser's result reaches a structured-data interpreter or "
        "database import routine, by real engine-computed dataflow, with every identity "
        "resolved and unambiguous. Execution timing is evidence only and never changes a "
        "verdict. Where the chain cannot be proven the site stays a candidate and the "
        "chain records why -- the layer under-reports rather than over-reports.")
    result["unresolved_source_identities"] = src_abstentions
    result["unresolved_consumer_identities"] = con_abstentions
    return result


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1], *(sys.argv[2:3] or [None])), indent=2))
