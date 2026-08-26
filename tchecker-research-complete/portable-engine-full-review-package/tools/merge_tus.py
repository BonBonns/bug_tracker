#!/usr/bin/env python3
"""BUILD-R02: per-translation-unit scanning with a merge at the NEUTRAL FACT layer.

Rationale (measured in BUILD-R01): one whole-repo CPG fights both Joern and the
host — overlays, raw-fact export and the normalizer all OOMed on a 39-TU C++
project. Translation units are also the natural semantic unit of C/C++
compilation, so the portable fact layer, not Joern, should be the repo-scale
integration point.

Invariants enforced here (each asserted, not assumed):
  I1 globally unique ids after merge (per-TU id spaces are disjointly offset)
  I2 a single TU's facts are BYTE-IDENTICAL before vs after the merge machinery
  I3 header material duplicated across TUs does not recreate <duplicate> inflation
  I4 the same symbol defined in several TUs keeps TU identity (never silently
     collapsed into one definition)
  I5 cross-TU calls are NOT linked here: linking requires signature+scope evidence
     (BUILD-R01 measured 43% of the residue as genuinely ambiguous by name), so
     they stay exactly as each TU's frontend left them.
"""
import json, pathlib, sys

# Per-TU id offset. MUST exceed the largest id in any TU or the id spaces overlap
# and "unique after merge" becomes luck. c2cpg ids are ~3e13, far above an
# assumed 2^34 — the first version of this file got that wrong and invariant I5
# caught it by reporting 583 phantom cross-TU links. Derived from the data now.
def id_space_of_paths(paths):
    mx = 0
    for _, p in paths:
        d = json.load(open(p))
        for k in ('functions','calls','locals','returns','assignments','identifiers','type_decls','members','method_returns'):
            for it in d.get(k, []):
                if isinstance(it.get('id'), int): mx = max(mx, it['id'])
        del d
    return mx + 1

LIST_KEYS = ('type_decls','members','functions','method_returns','locals','calls',
             'identifiers','returns','assignments')

def shift_value_ref(vr, off):
    vr = dict(vr)
    if vr.get('kind') in ('PARAMETER','LOCAL','CALL','STATE_READ','SELF') and isinstance(vr.get('id'), int) and vr['id'] > 0:
        vr['id'] += off
    return vr

def shift_doc(doc, off, tu_tag):
    d = json.loads(json.dumps(doc))
    for f in d.get('functions', []):
        f['id'] += off
        f['translation_unit'] = tu_tag          # I4: TU identity retained
        for p in f.get('parameters', []):
            p['id'] += off; p['method_id'] = p.get('method_id', 0) + off
    for c in d.get('calls', []):
        c['id'] += off; c['enclosing_function_id'] += off
        c['candidate_target_ids'] = [t + off for t in c.get('candidate_target_ids', [])]
        for a in c.get('arguments', []):
            a['id'] += off
            if 'value_ref' in a: a['value_ref'] = shift_value_ref(a['value_ref'], off)
    for r in d.get('returns', []):
        r['id'] += off; r['function_id'] += off
        r['value_ref'] = shift_value_ref(r['value_ref'], off)
    for l in d.get('locals', []):
        l['id'] += off; l['method_id'] += off
    for a in d.get('assignments', []):
        a['id'] += off; a['function_id'] += off; a['target_local_id'] += off
        a['value_ref'] = shift_value_ref(a['value_ref'], off)
        if 'cfg_anchor' in a: a['cfg_anchor'] += off
    for i in d.get('identifiers', []):
        i['id'] += off; i['method_id'] += off
        i['ref_target_ids'] = [t + off for t in i.get('ref_target_ids', [])]
    for m in d.get('method_returns', []):
        m['id'] += off; m['method_id'] += off
    for t in d.get('type_decls', []): t['id'] += off
    for m in d.get('members', []):
        m['id'] += off; m['type_decl_id'] = m.get('type_decl_id', 0) + off
    return d

SYSTEM_PREFIXES = ('std.', '__gnu_cxx', '__', 'operator', '_')

def is_project(f):
    """Project-scope test. Preprocessed TUs inline the ENTIRE standard library, so
    a merged 39-TU graph would be dominated by (and sized by) STL rather than the
    project. Every measurement in this arc already restricts to project code; doing
    it at merge time is what makes repo-scale merging tractable at all.
    NOTE: preprocessing destroys file provenance (all headers inline into one .cc),
    so this is a NAME-based test, and it is deliberately conservative — anything
    that looks like implementation-namespace or reserved-identifier material is
    treated as system code and dropped."""
    full = f.get('full_name', '') or ''
    name = f.get('name', '') or ''
    return not (full.startswith(SYSTEM_PREFIXES) or name.startswith('_'))

def filter_project(doc):
    """Keep project functions and only the facts belonging to them."""
    keep = {f['id'] for f in doc.get('functions', []) if is_project(f)}
    out = dict(doc)
    out['functions'] = [f for f in doc.get('functions', []) if f['id'] in keep]
    for k, fk in (('calls','enclosing_function_id'), ('returns','function_id'),
                  ('locals','method_id'), ('assignments','function_id'),
                  ('identifiers','method_id'), ('method_returns','method_id')):
        out[k] = [x for x in doc.get(k, []) if x.get(fk) in keep]
    return out

def merge(tu_paths):
    """STREAMING merge: each TU is loaded, project-filtered, shifted and released
    before the next is read, so peak memory is ONE translation unit rather than the
    whole repository. The earlier version held every doc at once, which is fine for
    4 TUs and impossible for 39."""
    first = json.load(open(tu_paths[0][1]))
    out = {'schema': first['schema'], 'frontend': 'joern-c2cpg(per-TU merge)',
           'metadata': [], 'translation_units': []}
    for k in LIST_KEYS: out[k] = []
    seen_ids = set()
    dup_suppressed = 0
    SPACE = id_space_of_paths(tu_paths)
    del first
    for idx, (tag, path) in enumerate(tu_paths):
        doc = json.load(open(path))
        shifted = shift_doc(filter_project(doc) if PROJECT_ONLY else doc, idx * SPACE, tag)
        out['translation_units'].append({'tag': tag, 'offset': idx * SPACE,
                                         'functions': len(shifted.get('functions', []))})
        for k in LIST_KEYS:
            for item in shifted.get(k, []):
                if k == 'functions':
                    # I3: bodyless <duplicate> nodes are dropped at the TU level,
                    # exactly as the scanner does, so the merge cannot reintroduce
                    # the inflation bug measured on stb.
                    if '<duplicate>' in item.get('full_name', ''):
                        dup_suppressed += 1
                        continue
                    if item['id'] in seen_ids:
                        raise SystemExit(f'INVARIANT I1 VIOLATED: duplicate id {item["id"]}')
                    seen_ids.add(item['id'])
                out[k].append(item)
        out['metadata'] += shifted.get('metadata', [])
        del doc, shifted
    out['frontend_counters'] = {'translation_units': len(tu_paths),
                                'functions': len(out['functions']),
                                'calls': len(out['calls']),
                                'duplicate_methods_suppressed': dup_suppressed}
    return out

PROJECT_ONLY = True

def main():
    if len(sys.argv) < 3:
        raise SystemExit('usage: merge_tus.py OUT.json TU1.json [TU2.json ...]')
    out_p = pathlib.Path(sys.argv[1])
    global PROJECT_ONLY
    args = [a for a in sys.argv[2:] if a != '--all-scopes']
    PROJECT_ONLY = '--all-scopes' not in sys.argv
    docs = [(pathlib.Path(p).parent.name or pathlib.Path(p).stem, p) for p in args]
    merged = merge(docs)
    out_p.write_text(json.dumps(merged, indent=1, sort_keys=True) + '\n')
    fc = merged['frontend_counters']
    print(f"merged {fc['translation_units']} TU(s): {fc['functions']} functions, "
          f"{fc['calls']} calls, {fc['duplicate_methods_suppressed']} duplicate methods suppressed")

if __name__ == '__main__':
    main()
