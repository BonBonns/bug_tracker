#!/usr/bin/env python3
"""Emit portable-reachingdef-facts/0.1 from the CFG, ANCHOR-BASED.

Reaching definitions run over STATEMENT ANCHORS (real CFG nodes). Every reaching
anchor is then expanded to ALL semantic defs anchored there, so a derived
contribution with no CFG node of its own (e.g. CPP_COMPOUND_PRIOR_VALUE) can never
be dropped for being invisible to the CFG.

Safety rules, in order:
  * a def with no anchor, or an anchor absent from the CFG, is NEVER filtered out
    (absence of an anchor is not evidence of unreachability) -> the whole fact is
    omitted for that use, leaving today's conservative behaviour;
  * a fact is emitted ONLY when it strictly narrows the def set;
  * an empty reaching set is never emitted (it would prove nothing).
usage: emit_reaching_defs.py PROGRAM.json RAW_DIR OUT.json
"""
import json, sys, pathlib
from collections import defaultdict, deque

def main():
    prog, raw, out = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
    doc = json.load(open(prog))
    succ = defaultdict(set); nodes_of = defaultdict(set)
    f = raw / 'cfg_edges.tsv'
    if not f.exists():
        json.dump({'schema': 'portable-reachingdef-facts/0.1', 'reaching_defs': []}, open(out, 'w'))
        print('RD: no cfg_edges.tsv; emitted empty'); return
    for l in f.read_text().splitlines():
        m, a, b = (int(x) for x in l.split('\t'))
        succ[a].add(b); nodes_of[m].add(a); nodes_of[m].add(b)

    by_fn = defaultdict(list)
    for a in doc.get('assignments', []): by_fn[a['function_id']].append(a)

    facts = []; stats = {'uses': 0, 'narrowed': 0, 'skipped_unanchored': 0}
    for fn in doc['functions']:
        fid = fn['id']; assigns = by_fn.get(fid, [])
        if not assigns: continue
        cfg_nodes = nodes_of.get(fid, set())
        if not cfg_nodes: continue
        anchors_of_local = defaultdict(set)
        defs_by_anchor = defaultdict(list)
        unanchored = defaultdict(list)
        for a in assigns:
            anc = a.get('cfg_anchor') or 0
            if anc and anc in cfg_nodes:
                anchors_of_local[a['target_local_id']].add(anc)
                defs_by_anchor[anc].append(a)
            else:
                unanchored[a['target_local_id']].append(a)
        rets = [r for r in doc.get('returns', [])
                if r['function_id'] == fid and r['value_ref']['kind'] == 'LOCAL']
        for r in rets:
            lid = r['value_ref']['id']
            local_defs = [a for a in assigns if a['target_local_id'] == lid]
            if len(local_defs) < 2: continue
            stats['uses'] += 1
            if unanchored[lid]:
                # cannot prove anything about defs we cannot place in the CFG
                stats['skipped_unanchored'] += 1
                continue
            use = r['id']
            if use not in cfg_nodes: continue
            nodes = cfg_nodes | {use}
            preds = defaultdict(set)
            for x in nodes:
                for y in succ.get(x, ()):
                    if y in nodes: preds[y].add(x)
            all_anchors = anchors_of_local[lid]
            IN = {n: set() for n in nodes}; OUT = {n: set() for n in nodes}
            work = deque(nodes)
            while work:
                n = work.popleft()
                newin = set()
                for p in preds.get(n, ()): newin |= OUT[p]
                if n in all_anchors:
                    newout = {n}
                else:
                    newout = set(newin)
                if newout != OUT[n] or newin != IN[n]:
                    IN[n] = newin; OUT[n] = newout
                    for s2 in succ.get(n, ()):
                        if s2 in nodes: work.append(s2)
            reaching_anchors = IN.get(use, set()) & all_anchors
            # EXPAND anchors -> ALL semantic defs anchored there
            def_ids = sorted({a['id'] for anc in reaching_anchors for a in defs_by_anchor[anc]
                              if a['target_local_id'] == lid})
            if not def_ids or len(def_ids) >= len(local_defs): continue
            stats['narrowed'] += 1
            facts.append({'use_id': use, 'function_id': fid, 'local_id': lid,
                          'def_ids': def_ids, 'resolution': 'EXACT',
                          'derivation': {'origin': 'FRONTEND_DERIVED',
                                         'rule': 'CFG_REACHING_DEFINITIONS_ANCHORED',
                                         'source_node_ids': [use] + sorted(reaching_anchors)}})
    json.dump({'schema': 'portable-reachingdef-facts/0.1', 'reaching_defs': facts},
              open(out, 'w'), indent=1, sort_keys=True)
    print(f"RD: uses={stats['uses']} narrowed={stats['narrowed']} "
          f"skipped_unanchored={stats['skipped_unanchored']} facts={len(facts)}")

if __name__ == '__main__':
    main()
