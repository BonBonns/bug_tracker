#!/usr/bin/env python3
"""Loop-control divergence / validation-bypass verdict — the JS/TS analogue of
the Elementor Pro Upload::validation() early-return bug.

PATTERN
-------
A per-element validation loop uses `return` where it should use `continue`: on
the first skippable element (an empty upload slot) it abandons validation of
every remaining sibling. A paired processing loop over the SAME collection uses
`continue` for the same skip predicate and still reaches a sink (file write)
with the unvalidated siblings.

CORE DISCRIMINATOR (measured, straight from the original code)
  A per-element early `return` that records NO error first is a SILENT
  abandonment — the bug. A `return` preceded by an error-recording call
  (addError/…) is SAFE: the whole request is rejected downstream, so skipping
  siblings is harmless. `continue` is always safe (correct skip).

VERDICTS (CANDIDATE, never "VULNERABLE" — the engine's stance)
  CANDIDATE_VALIDATION_BYPASS        a silent per-element RETURN in a validation
     loop, AND a paired processing loop over the same collection uses CONTINUE
     and reaches a sink. Highest confidence: the two-loop divergence is present.
  CANDIDATE_SILENT_LOOP_RETURN       a silent per-element RETURN in a loop, but
     no paired sink-reaching processing loop was found. Still suspicious (the
     remaining-element validation is abandoned), lower confidence.
  SAFE_RECORDS_ERROR                 the RETURN records an error first.
  SAFE_CONTINUE                      the exit is `continue` (correct skip).

CEILINGS
  * "Paired processing loop" is matched by normalized collection expression
    (`files[id]` vs `files[id].entries()`), intra-repo. A processing loop in an
    unscanned module is missed (under-approx, never a false alarm).
  * per-element-ness is a lexical test (guard references the loop's element
    var). A guard that tests the element via an alias is under-approximated.
  * Sink reachability inside the processing loop is loop-membership, not a full
    CFG path; a guard that always `continue`s before the sink would need a CFG
    pass to exonerate (future work).
"""
import json, sys, re
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required validation-bypass fact file missing: {p}")
    out, seen = [], set()
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            xs = ln.split("\t")
            k = tuple(xs)
            if k not in seen:
                seen.add(k); out.append(xs)
    return out


def _norm_collection(code):
    """Normalize a loop collection expression so `files[id]` and
    `files[id].entries()` (or `.values()`/`Object.entries(...)`) match."""
    c = code.strip()
    c = re.sub(r"\.entries\(?\s*\)?$", "", c)
    c = re.sub(r"\.values\(?\s*\)?$", "", c)
    c = re.sub(r"^Object\.(entries|values)\(\s*(.+?)\s*\)?$", r"\2", c)
    return c


def derive(raw):
    raw = Path(raw)

    # Prefer the NAMED enclosing method (drop the ::program duplicate rows).
    def named(rows, method_idx=1):
        best = {}
        for r in rows:
            key = tuple(x for i, x in enumerate(r) if i != method_idx)
            m = r[method_idx]
            # a named method fullname contains ":<name>" after ::program
            is_named = ":" in m.split("::program", 1)[-1]
            if key not in best or (is_named and not best[key][1]):
                best[key] = (r, is_named)
        return [v[0] for v in best.values()]

    exits = named(_rows(raw / "loop_exits.tsv", 9))
    colls = named(_rows(raw / "loop_collections.tsv", 5))
    sinks = named(_rows(raw / "loop_sink_sites.tsv", 6))

    # collection expr per (file, method, loop_line)
    coll_of = {(r[0], r[1], r[2]): _norm_collection(r[3]) for r in colls}

    # processing loops: (normalized collection) -> list of loops that use
    # CONTINUE on a per-element guard AND contain a sink.
    sink_loops = {(r[0], r[1], r[2]) for r in sinks}
    continue_loops = {}
    for f_, meth, lline, kind, eline, guard, errf, perelem, retval in exits:
        if kind == "CONTINUE" and perelem == "true":
            key = (f_, meth, lline)
            col = coll_of.get(key)
            if col is not None and key in sink_loops:
                continue_loops.setdefault(col, []).append({"file": f_, "method": meth, "loop_line": lline})

    findings = []
    for f_, meth, lline, kind, eline, guard, errf, perelem, retval in exits:
        if kind != "RETURN":
            if kind == "CONTINUE":
                findings.append({"file": f_, "method": meth, "loop_line": lline,
                                 "exit_line": eline, "verdict": "SAFE_CONTINUE"})
            continue
        if perelem != "true":
            # whole-collection return (e.g. maxFiles guard) — not the pattern
            findings.append({"file": f_, "method": meth, "loop_line": lline,
                             "exit_line": eline, "verdict": "SAFE_WHOLE_COLLECTION_RETURN"})
            continue
        if retval == "true":
            # SEARCH-and-return: returns a found value on a (positive) match, not
            # the Elementor abandonment shape which returns void. Not a bypass.
            findings.append({"file": f_, "method": meth, "loop_line": lline,
                             "exit_line": eline, "verdict": "SAFE_SEARCH_RETURN",
                             "guard": guard})
            continue
        if errf == "true":
            findings.append({"file": f_, "method": meth, "loop_line": lline,
                             "exit_line": eline, "verdict": "SAFE_RECORDS_ERROR",
                             "guard": guard})
            continue
        # silent per-element RETURN — the dangerous shape
        col = coll_of.get((f_, meth, lline))
        paired = continue_loops.get(col, []) if col else []
        if paired:
            findings.append({"file": f_, "method": meth, "loop_line": lline,
                             "exit_line": eline, "verdict": "CANDIDATE_VALIDATION_BYPASS",
                             "collection": col, "guard": guard,
                             "paired_processing_loops": paired})
        else:
            findings.append({"file": f_, "method": meth, "loop_line": lline,
                             "exit_line": eline, "verdict": "CANDIDATE_SILENT_LOOP_RETURN",
                             "collection": col, "guard": guard})

    return {
        "schema": "validation-bypass-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags a silent per-element `return` "
                 "in a validation loop (no error recorded first) that abandons "
                 "validation of remaining elements — the JS/TS shape of the "
                 "Elementor Pro Upload::validation() bypass. Escalates when a "
                 "paired processing loop over the same collection uses `continue` "
                 "and reaches a sink."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "loop-out/raw"), indent=2))
