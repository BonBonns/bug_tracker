#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY-R01 -- quote-boundary parser-correctness reducer.

Reads the graph facts emitted by producers/escape_parity_facts.sc and joins them BY
NODE IDENTITY into per-site records. It never re-derives facts from source text, never
merges two sites that share pattern text but not identity, and never guesses past an
unresolved construct.

SCOPE. This is a software-reliability and data-integrity property. It reports whether a
quoted-string boundary rule is structurally capable of establishing escape-run parity,
and whether a delayed transform-to-consumer chain is provable. It makes no impact,
severity, exploitability, or any comparable claim, and `reportable` is false on every
record in this revision.

CLASSIFICATIONS (the only two)
  ESCAPE_PARITY_PARSER_CANDIDATE
      the boundary rule is structurally incomplete: it decides the quote by inspecting
      a fixed single preceding position (or an equivalent one-character test) instead
      of the parity of the whole consecutive escape run. Requires nothing else.
  DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE
      the above, PLUS a proven chain: a delayed source (stored file / archive / dump /
      database row) reaches the parsing transformation, and the transformation's result
      reaches a structured-data interpreter or database import routine, with every
      identity on that chain resolved and the linkage unambiguous.

Everything else is a NEGATIVE (with a reason) or an ABSTENTION (with a reason).
Abstention is required, never optional, when regex construction, replacement-callback
identity, delayed-source identity, transformation order, or downstream-consumer
identity is unresolved or ambiguous.

Execution timing (cron/scheduled/deferred registration) is carried as evidence only.
It is never treated as a guard and never changes a classification.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from regex_boundary_model import (  # noqa: E402
    classify_pattern, INCOMPLETE_VERDICTS, PARITY_ESTABLISHED,
    ESCAPE_IMPOSSIBLE_IN_BODY, NO_ESCAPE_AWARENESS, NO_QUOTED_STRING_CONSTRUCT,
    UNCLASSIFIED_BOUNDARY_SHAPE,
)

CANDIDATE = "ESCAPE_PARITY_PARSER_CANDIDATE"
REACHABLE = "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"
NEGATIVE = "NEGATIVE"
ABSTAINED = "ABSTAINED"

# a fixed single-position index test can never establish run parity, by construction
SINGLE_POSITION_INDEX_CHECK = "SINGLE_POSITION_INDEX_CHECK"
PARITY_ESTABLISHED_IN_METHOD = "PARITY_ESTABLISHED_IN_METHOD"
UNRESOLVED_REGEX_CONSTRUCTION = "UNRESOLVED_REGEX_CONSTRUCTION"


def _rows(path, ncols):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < ncols:
            parts = parts + [""] * (ncols - len(parts))
        out.append(parts[:ncols])
    return out


def _unescape(s):
    """Undo the producer's field escaping (it escapes \\, tab and newline)."""
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "\\":
                out.append("\\"); i += 2; continue
            if nxt == "n":
                out.append("\n"); i += 2; continue
            if nxt == "t":
                out.append("\t"); i += 2; continue
        out.append(s[i]); i += 1
    return "".join(out)


def _pkg(file_path):
    """Package/unit key: the first path segment, matching this study's convention."""
    return file_path.split("/")[0] if "/" in file_path else file_path


def derive(raw_dir):
    raw = Path(raw_dir)

    regex_sites = _rows(raw / "regex_sites.tsv", 9)
    index_checks = _rows(raw / "parser_index_checks.tsv", 11)
    quote_sites = _rows(raw / "parser_quote_sites.tsv", 7)
    parity_rows = _rows(raw / "parity_mechanisms.tsv", 6)
    source_rows = _rows(raw / "delayed_sources.tsv", 9)
    transform_rows = _rows(raw / "transform_calls.tsv", 8)
    callback_rows = _rows(raw / "replacement_callbacks.tsv", 6)
    consumer_rows = _rows(raw / "consumers.tsv", 8)
    edge_rows = _rows(raw / "chain_edges.tsv", 5)
    timing_rows = _rows(raw / "execution_timing.tsv", 5)

    # ---- indexes, all keyed by real node identity ------------------------------
    parity_methods = {}                       # method_id -> [mechanisms]
    for f_, meth, mid, line, nid, mech in parity_rows:
        parity_methods.setdefault(mid, []).append({"mechanism": mech, "node_id": nid,
                                                   "line": line})

    replaces = {}                             # replace_call_id -> row
    encodes = set()
    for f_, meth, line, nid, family, ident, regex_arg, res in transform_rows:
        if family == "REPLACE":
            replaces[nid] = {"file": f_, "method": meth, "line": line, "node_id": nid,
                             "regex_node_id": regex_arg, "resolution": res,
                             "callee": ident}
        elif family == "ENCODE":
            encodes.add(nid)

    callbacks = {}                            # replace_call_id -> row
    for f_, line, rid, cbid, kind, res in callback_rows:
        callbacks[rid] = {"callback_node_id": cbid, "kind": kind, "resolution": res}

    sources = {}                              # source_call_id -> row
    unresolved_sources = []
    for f_, meth, line, nid, ident, mod, imp, res, kind in source_rows:
        rec = {"file": f_, "method": meth, "line": line, "node_id": nid,
               "api_identity": ident, "module_identity": mod, "import_node_id": imp,
               "resolution": res, "source_kind": kind}
        if res == "RESOLVED_IMPORT":
            sources[nid] = rec
        else:
            unresolved_sources.append(rec)

    consumers, log_only, unresolved_consumers = {}, {}, {}
    for f_, meth, line, nid, ident, mod, kind, res in consumer_rows:
        rec = {"file": f_, "method": meth, "line": line, "node_id": nid,
               "consumer_identity": ident, "kind": kind, "resolution": res}
        if kind == "LOGGING_ONLY":
            log_only[nid] = rec
        elif res != "RESOLVED":
            unresolved_consumers[nid] = rec
        else:
            consumers[nid] = rec

    edges = {}                                # edge_kind -> {from_id -> {to_id}}
    for fk, fid, tk, tid, kind in edge_rows:
        edges.setdefault(kind, {}).setdefault(fid, set()).add(tid)

    timing_by_method = {}
    for f_, meth, line, nid, kind in timing_rows:
        timing_by_method.setdefault(meth, []).append({"kind": kind, "node_id": nid,
                                                      "line": line})

    def edges_into(kind, target_id):
        return {frm for frm, tos in edges.get(kind, {}).items() if target_id in tos}

    def edges_from(kind, from_id):
        return set(edges.get(kind, {}).get(from_id, set()))

    # a consumer fed by more than one distinct replace site cannot be attributed
    ambiguous_consumers = set()
    for cons_id in list(consumers):
        feeders = edges_into("REPLACE2CONSUMER", cons_id) | edges_into("ENCODE2CONSUMER", cons_id)
        replace_feeders = {f for f in feeders if f in replaces}
        for enc in {f for f in feeders if f in encodes}:
            replace_feeders |= {r for r in edges_into("REPLACE2ENCODE", enc) if r in replaces}
        distinct_rules = {replaces[r]["regex_node_id"] for r in replace_feeders
                          if replaces[r]["regex_node_id"] not in ("", "-1")}
        if len(distinct_rules) > 1:
            ambiguous_consumers.add(cons_id)

    findings = []

    # ---- boundary sites: regex ---------------------------------------------
    for f_, meth, mid, line, nid, resolution, pattern, flags, detail in regex_sites:
        pattern = _unescape(pattern)
        rec = {
            "file": f_, "package": _pkg(f_), "method": meth, "method_node_id": mid,
            "line": line, "site_kind": "REGEX_LITERAL" if resolution == "RESOLVED_LITERAL"
            else "REGEX_CONSTRUCTED", "site_node_id": nid,
            "pattern_resolution": resolution, "pattern": pattern, "flags": flags,
            "escape_char": "\\",
        }
        if resolution == "UNRESOLVED_DYNAMIC":
            rec.update({"boundary_rule": UNRESOLVED_REGEX_CONSTRUCTION,
                        "classification": ABSTAINED,
                        "abstention_reason": UNRESOLVED_REGEX_CONSTRUCTION})
            _attach_chain(rec, nid, replaces, callbacks, sources, consumers, log_only,
                          unresolved_consumers, ambiguous_consumers, encodes, edges_into,
                          edges_from, timing_by_method, chain_allowed=False)
            findings.append(rec)
            continue

        verdict, detail_v = classify_pattern(pattern)
        rec["boundary_rule"] = verdict
        if verdict in INCOMPLETE_VERDICTS and mid in parity_methods:
            # the enclosing method itself establishes parity elsewhere
            rec["boundary_rule"] = PARITY_ESTABLISHED_IN_METHOD
            rec["parity_mechanisms"] = parity_methods[mid]
            verdict = PARITY_ESTABLISHED_IN_METHOD
        _finalize(rec, verdict, detail_v, nid, replaces, callbacks, sources, consumers,
                  log_only, unresolved_consumers, ambiguous_consumers, encodes,
                  edges_into, edges_from, timing_by_method)
        findings.append(rec)

    # ---- boundary sites: character-scanning custom parsers -------------------
    # Every quoted-string scanner is emitted as a record, so a parity-correct
    # hand-written parser is a CLASSIFIED NEGATIVE, never an absent one.
    checks_by_method = {}
    for (f_, meth, mid, line, check_id, quote_id, esc_id, idx_id, offset, base,
         idxname) in index_checks:
        checks_by_method.setdefault(mid, []).append({
            "check_node_id": check_id, "quote_cmp_node_id": quote_id,
            "escape_cmp_node_id": esc_id, "index_expr_node_id": idx_id,
            "index_offset": offset, "base_expr": base, "index_var": idxname,
            "line": line})

    for f_, meth, mid, line, cmp_id, other_id, char_kind in quote_sites:
        rec = {
            "file": f_, "package": _pkg(f_), "method": meth, "method_node_id": mid,
            "line": line, "site_kind": "CUSTOM_PARSER", "site_node_id": cmp_id,
            "compared_expr_node_id": other_id, "char_access_kind": char_kind,
            "escape_char": "\\", "pattern_resolution": "N/A", "pattern": "", "flags": "",
        }
        my_checks = checks_by_method.get(mid, [])
        if mid in parity_methods:
            rec["parity_mechanisms"] = parity_methods[mid]
            verdict = PARITY_ESTABLISHED_IN_METHOD
        elif my_checks:
            rec["single_position_checks"] = my_checks
            verdict = SINGLE_POSITION_INDEX_CHECK
        else:
            verdict = NO_ESCAPE_AWARENESS
        rec["boundary_rule"] = verdict
        _finalize(rec, verdict, "", None, replaces, callbacks, sources, consumers,
                  log_only, unresolved_consumers, ambiguous_consumers, encodes,
                  edges_into, edges_from, timing_by_method, method_id=mid,
                  sources_by_method=True)
        findings.append(rec)

    for rec in findings:
        rec["reportable"] = False

    return {
        "schema": "escape-parity-boundary-r01/0.1",
        "property": "quoted-string escape-run parity at the quote boundary",
        "note": (
            "Software-reliability / data-integrity property. Classifications are derived "
            "from CPG node identities and a structural parse of each resolved regex "
            "pattern; no classification is derived from source-text substring matching. "
            "Delayed, scheduled or administrative execution is recorded as execution-"
            "timing evidence only and is never treated as a guard. Abstention is "
            "mandatory wherever regex construction, replacement-callback identity, "
            "delayed-source identity, transformation order or downstream-consumer "
            "identity is unresolved or ambiguous. No impact, severity or exploitability "
            "claim of any kind is made; reportable is false on every record."),
        "classification_vocabulary": [CANDIDATE, REACHABLE],
        "findings": findings,
    }


def _attach_chain(rec, regex_node_id, replaces, callbacks, sources, consumers, log_only,
                  unresolved_consumers, ambiguous_consumers, encodes, edges_into,
                  edges_from, timing_by_method, chain_allowed=True, method_id=None,
                  sources_by_method=False):
    """Attach the delayed-source -> transform -> consumer chain evidence, by identity."""
    chain = {"replace_sites": [], "delayed_sources": [], "encodes": [], "consumers": [],
             "logging_only_consumers": [], "status": "NOT_ESTABLISHED", "reasons": []}
    rec["execution_timing_evidence"] = timing_by_method.get(rec.get("method", ""), [])

    if sources_by_method:
        # a custom parser has no replace call: record the delayed sources that occur in
        # the same file, as evidence only -- never as a proven chain.
        same_file = [s for s in sources.values() if s["file"] == rec["file"]]
        chain["delayed_sources"] = same_file
        chain["reasons"].append("CUSTOM_PARSER_CHAIN_NOT_MODELLED")
        rec["chain"] = chain
        return

    my_replaces = [r for r in replaces.values() if r["regex_node_id"] == regex_node_id]
    chain["replace_sites"] = my_replaces
    if not my_replaces:
        chain["reasons"].append("NO_TRANSFORMATION_USES_THIS_RULE")
        rec["chain"] = chain
        return

    for r in my_replaces:
        rid = r["node_id"]
        cb = callbacks.get(rid)
        if cb:
            r["callback"] = cb
            if cb["resolution"] != "RESOLVED":
                chain["reasons"].append(cb["resolution"])
        srcs = [sources[s] for s in edges_into("DELAYED_SOURCE2REPLACE", rid) if s in sources]
        chain["delayed_sources"].extend(srcs)
        encs = [e for e in edges_from("REPLACE2ENCODE", rid) if e in encodes]
        chain["encodes"].extend(encs)
        cons = set(edges_from("REPLACE2CONSUMER", rid)) | set(edges_from("REPLACE2LOGGING", rid))
        for e in encs:
            cons |= set(edges_from("ENCODE2CONSUMER", e)) | set(edges_from("ENCODE2LOGGING", e))
        for c in cons:
            if c in consumers:
                chain["consumers"].append(consumers[c])
                if c in ambiguous_consumers:
                    chain["reasons"].append("AMBIGUOUS_CONSUMER_LINKAGE")
            elif c in log_only:
                chain["logging_only_consumers"].append(log_only[c])
            elif c in unresolved_consumers:
                chain["reasons"].append("UNRESOLVED_CONSUMER_IDENTITY")

    if not chain["delayed_sources"]:
        chain["reasons"].append("NO_DELAYED_SOURCE_REACHES_TRANSFORMATION")
    if not chain["consumers"]:
        chain["reasons"].append("NO_STRUCTURED_TEXT_CONSUMER_REACHED")

    blocking = [x for x in chain["reasons"]
                if x in ("UNRESOLVED_CALLBACK_IDENTITY", "AMBIGUOUS_CALLBACK_IDENTITY",
                         "UNRESOLVED_CONSUMER_IDENTITY", "AMBIGUOUS_CONSUMER_LINKAGE")]
    if chain["delayed_sources"] and chain["consumers"] and not blocking:
        chain["status"] = "ESTABLISHED"
    elif blocking:
        chain["status"] = "ABSTAINED"
    rec["chain"] = chain


def _finalize(rec, verdict, detail_v, regex_node_id, replaces, callbacks, sources,
              consumers, log_only, unresolved_consumers, ambiguous_consumers, encodes,
              edges_into, edges_from, timing_by_method, method_id=None,
              sources_by_method=False):
    incomplete = verdict in INCOMPLETE_VERDICTS or verdict == SINGLE_POSITION_INDEX_CHECK
    _attach_chain(rec, regex_node_id, replaces, callbacks, sources, consumers, log_only,
                  unresolved_consumers, ambiguous_consumers, encodes, edges_into,
                  edges_from, timing_by_method, method_id=method_id,
                  sources_by_method=sources_by_method)

    if verdict == UNCLASSIFIED_BOUNDARY_SHAPE:
        rec["classification"] = ABSTAINED
        rec["abstention_reason"] = "UNMODELLED_BOUNDARY_SHAPE"
        rec["abstention_detail"] = detail_v
        return
    if not incomplete:
        rec["classification"] = NEGATIVE
        rec["negative_reason"] = verdict
        return

    chain = rec["chain"]
    if chain["status"] == "ESTABLISHED":
        rec["classification"] = REACHABLE
    elif chain["status"] == "ABSTAINED":
        # the boundary rule stands on its own; only the chain is unprovable
        rec["classification"] = CANDIDATE
        rec["chain_abstention_reason"] = sorted(set(
            x for x in chain["reasons"]
            if x in ("UNRESOLVED_CALLBACK_IDENTITY", "AMBIGUOUS_CALLBACK_IDENTITY",
                     "UNRESOLVED_CONSUMER_IDENTITY", "AMBIGUOUS_CONSUMER_LINKAGE")))
    else:
        rec["classification"] = CANDIDATE


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
