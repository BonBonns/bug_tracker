#!/usr/bin/env python3
"""Path-scoped transform identity (separately gated milestone).

Works OUTWARD FROM THE PROPAGATION RELATION. For each established source->sink
alternative, transform membership is exactly the ordered CALL nodes that the frozen
propagation producer already placed on that alternative's established flow
(propagation_relations.transform_chain = "pos:callNode:callee ; ..."). A call is a
transform for an alternative ONLY if its stable CPG node identity lies on that
alternative's path. Identity of each path-member call is then resolved via the existing
R-series import facts (import_bindings.tsv); UNKNOWN when it is not an import binding.

This does NOT recompute dataflow, does NOT ask "what is data-dependent on the source",
and does NOT modify the frozen propagation producer or the adjudicator. Output format is
drop-in compatible with transform_identity.tsv (8 columns), so the adjudicator consumes
it unchanged:
   sink_node, source_node, order(path_position), call_node, callee,
   module_spec, member, identity_status(ESTABLISHED|UNKNOWN)

Conceptual invariant preserved for every emitted row:
   path_membership = ESTABLISHED  (it is on the established flow)
   semantic_identity = <module#member> when resolved, else UNKNOWN
i.e. a call can be a known path member whose semantic family is still UNKNOWN.
"""
import sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "find-out/raw")


def rows(name, n):
    p = RAW / name
    return [f for f in (ln.split("\t") for ln in (p.read_text().splitlines() if p.exists() else [])) if len(f) == n]


# identity table from existing import facts: local-name -> module specifier
importmap = {}
for r in (ln.split("\t") for ln in (RAW / "import_bindings.tsv").read_text().splitlines()
          if (RAW / "import_bindings.tsv").exists()):
    if len(r) >= 4:
        file_, spec, member, as_ = r[0], r[1], r[2], r[3]
        if as_ and not as_.startswith("_tmp"):
            importmap[as_] = spec            # {as} = require(spec)  ->  as resolves to spec#as


def resolve(callee):
    if callee in importmap:
        return importmap[callee], callee, "ESTABLISHED"     # module#member established via import fact
    return "", "", "UNKNOWN"                                # path member, semantic identity UNKNOWN


out = []
for r in rows("propagation_relations.tsv", 9):
    sink_node, sink_line, status, source_node, source_line, source_code, chain, qual, prov = r
    if status != "ESTABLISHED":
        continue
    if not chain.strip():
        continue   # direct source->sink, no path-member transforms (valid: zero transforms)
    for seg in chain.split(" ; "):
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split(":")
        if len(parts) < 3:
            continue
        pos, call_node, callee = parts[0], parts[1], ":".join(parts[2:])
        spec, member, idstat = resolve(callee)
        out.append([sink_node, source_node, pos, call_node, callee, spec, member, idstat])

# stable ordering: by sink, source, path position
out.sort(key=lambda x: (x[0], x[1], int(x[2])))
dest = RAW / "path_transform_identity.tsv"
dest.write_text("\n".join("\t".join(x) for x in out) + ("\n" if out else ""))
print(f"PATH_TRANSFORM_IDENTITY_COMPLETE: {dest}  ({len(out)} path-member transforms)")
