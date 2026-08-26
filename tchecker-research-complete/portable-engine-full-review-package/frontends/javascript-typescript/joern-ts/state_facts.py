#!/usr/bin/env python3
"""Derive language-neutral keyed-state facts (StateWrite / StateRead) from real Joern
operator+identifier facts, for property/index state that has no first-class CPG node.

Neutral model (no JS/PHP syntax in the shape):
  StateWrite(function, receiver_ref, receiver_location, key_selector, value_ref, resolution)
  StateRead (function, receiver_ref, receiver_location, key_selector,            resolution)

  receiver_location = {root_ref, path:[key_selector, ...]}
  makes separately-created accessor AST nodes comparable without flattening
  different bindings or dynamic selectors into one object.

  key_selector = {kind: LITERAL, value: "<k>"}      -> STATIC slot
               | {kind: DYNAMIC, ref: <identifier>}  -> DYNAMIC slot (AMBIGUOUS by construction)

Resolution of a keyed write/read is EXACT only when receiver identity is a single
value AND the key is a static literal. A dynamic key, or a receiver we can't pin to
one value, yields AMBIGUOUS. Nothing here hardens either.

This composes three Joern CALL nodes that together encode `recv[key] = val`:
  <operator>.assignment( <operator>.indexAccess(recv, key), value )
and the read form `recv[key]`:
  <operator>.indexAccess(recv, key)   [not the arg1 of an assignment]

It is purely structural + dataflow (identifier refsTo); it does not read member decls
(which real jssrc2cpg types as ANY) and adds no dedicated language node.
"""
import base64, json, sys
from pathlib import Path

def _dd(s):
    try:
        import base64 as _b
        return _b.b64decode(s).decode()
    except Exception:
        return ''

def _d(s): return base64.b64decode(s).decode() if s else ''

def load(raw):
    raw = Path(raw)
    def rows(name, n):
        p = raw / name
        if not p.exists(): return []
        return [l.split('\t') for l in p.read_text().splitlines() if l.strip() and len(l.split('\t')) >= n]
    methods = {int(r[0]): {'name': _d(r[1]), 'full_name': _d(r[2])} for r in rows('methods.tsv', 10)}
    calls = {}
    for r in rows('calls.tsv', 11):
        calls[int(r[0])] = {'id': int(r[0]), 'method_id': int(r[1]), 'name': _d(r[2]), 'mfn': _d(r[3]), 'code': _d(r[6])}
    args = {}
    for r in rows('arguments.tsv', 8):
        args.setdefault(int(r[1]), []).append({
            'node_id': int(r[0]), 'index': int(r[2]), 'code': _d(r[4]),
            'name': _d(r[5]), 'type': _d(r[6])})
    for v in args.values(): v.sort(key=lambda a: a['index'])
    idents = {}
    for r in rows('identifiers.tsv', 7):
        idents[int(r[0])] = {'name': _d(r[2]), 'refs': [int(x) for x in r[6].split(',') if x.strip()]}
    return methods, calls, args, idents

def _key_selector(key_arg):
    code = key_arg['code']
    if len(code) >= 2 and code[0] in '"\'' and code[-1] in '"\'':
        return {'kind': 'LITERAL', 'value': code[1:-1]}
    # numeric literal
    if code.isdigit():
        return {'kind': 'LITERAL', 'value': code}
    return {'kind': 'DYNAMIC', 'ref': key_arg['name'] or code}

def _receiver_ref(recv_arg):
    return {'name': recv_arg['name'] or recv_arg['code'], 'type': recv_arg['type']}

def derive(raw):
    methods, calls, args, idents = load(raw)
    call_ids = set(calls)
    # frontend-side reference resolution (0.4): receiver_ref / value_ref so the core
    # never maps names to bindings. Same resolution rules as program-facts 0.3.
    rawp = Path(raw)
    param_by_name, param_ids, local_ids, lit = {}, set(), set(), {}
    for l in (rawp/'parameters.tsv').read_text().splitlines():
        r = l.split('\t')
        pid, mid, name = int(r[0]), int(r[1]), _dd(r[3])
        param_ids.add(pid); param_by_name[(mid, name)] = pid
    if (rawp/'locals.tsv').exists():
        for l in (rawp/'locals.tsv').read_text().splitlines():
            r = l.split('\t'); local_ids.add(int(r[0]))
            param_by_name.setdefault((int(r[1]), _dd(r[2])), int(r[0]))
    if (rawp/'literals.tsv').exists():
        for l in (rawp/'literals.tsv').read_text().splitlines():
            r = l.split('\t'); lit[int(r[0])] = _dd(r[1])
    ident_ref = {}
    for l in (rawp/'identifiers.tsv').read_text().splitlines():
        r = l.split('\t')
        refs = [int(x) for x in r[6].split(',') if x.strip()]
        ident_ref.setdefault(int(r[0]), refs)
    def vref(node_id, mid, name_hint='', code_hint=''):
        if name_hint == 'this' or code_hint == 'this':
            return {'kind': 'SELF', 'id': mid, 'code': 'this'}
        if node_id in param_ids: return {'kind': 'PARAMETER', 'id': node_id, 'code': code_hint or name_hint}
        if node_id in local_ids: return {'kind': 'LOCAL', 'id': node_id, 'code': code_hint or name_hint}
        if node_id in call_ids:  return {'kind': 'CALL', 'id': node_id, 'code': code_hint}
        if node_id in lit:       return {'kind': 'CONSTANT', 'id': -1, 'code': lit[node_id]}
        for t in ident_ref.get(node_id, []):
            if t in param_ids: return {'kind': 'PARAMETER', 'id': t, 'code': name_hint}
            if t in local_ids: return {'kind': 'LOCAL', 'id': t, 'code': name_hint}
        if name_hint and (mid, name_hint) in param_by_name:
            t = param_by_name[(mid, name_hint)]
            return {'kind': 'PARAMETER' if t in param_ids else 'LOCAL', 'id': t, 'code': name_hint}
        c = (code_hint or '').strip()
        if c.startswith(('"', "'")): return {'kind': 'CONSTANT', 'id': -1, 'code': c}
        return {'kind': 'UNKNOWN', 'id': -1, 'code': code_hint or name_hint}
    # A keyed accessor is either recv[key] (indexAccess) or recv.field (fieldAccess).
    # Both encode (receiver, key/field) state; unify them under one neutral selector.
    # Block membership (call -> enclosing block ids) for object-literal/spread
    # lowering composition: `X = BLOCK{ ...ops on _tmp... }` means _tmp IS X.
    call_blocks = {}
    if (rawp/'call_blocks.tsv').exists():
        for l in (rawp/'call_blocks.tsv').read_text().splitlines():
            r = l.rstrip('\n').split('\t')
            call_blocks[int(r[0])] = set(int(x) for x in r[1].split(',') if x.strip())
    # tmp-alias: RHS block id -> (LHS receiver_ref, assignment cid)
    block_alias = {}
    for cid, c in calls.items():
        if c['name'] != '<operator>.assignment':
            continue
        aa = args.get(cid, [])
        if len(aa) >= 2 and aa[0]['name'] and not aa[1]['name']:
            rhs_node = aa[1]['node_id']
            if rhs_node not in calls and rhs_node not in lit:
                block_alias[rhs_node] = (vref(aa[0]['node_id'], c['method_id'], aa[0]['name'], aa[0]['code']), cid)
    def rebound_receiver(write_cid, recv_ref, recv_name):
        if not (recv_name or '').startswith('_tmp'):
            return recv_ref, None
        for b in call_blocks.get(write_cid, ()):  
            if b in block_alias:
                return block_alias[b][0], b
        return recv_ref, None
    accessors = {cid: c for cid, c in calls.items()
                 if c['name'] in ('<operator>.indexAccess', '<operator>.fieldAccess')}
    writes, reads = [], []
    consumed_as_write_target = set()

    def selector_for(acc):
        aa = args.get(acc['id'], [])
        if len(aa) < 2:
            return None, None
        recv, key = aa[0], aa[1]
        if acc['name'] == '<operator>.fieldAccess':
            # arg2 is a field identifier; its code is the field name (always static).
            return recv, {'kind': 'LITERAL', 'value': key['code']}
        return recv, _key_selector(key)

    def receiver_location_for(acc, seen=None):
        """Canonical root + property path for an accessor's receiver.

        Joern creates distinct CALL node IDs for separate occurrences of the same
        nested expression. Node identity therefore cannot join a read and write of
        `input.profile.url`. The binding identity of `input` plus the ordered
        selector path can, without equating a different root object.
        """
        seen = set() if seen is None else set(seen)
        if acc['id'] in seen:
            return {'root_ref': {'kind': 'UNKNOWN', 'id': -1, 'code': acc['code']}, 'path': []}
        seen.add(acc['id'])
        recv, _ = selector_for(acc)
        if recv is None:
            return {'root_ref': {'kind': 'UNKNOWN', 'id': -1, 'code': acc['code']}, 'path': []}
        inner = accessors.get(recv['node_id'])
        if inner is None:
            return {
                'root_ref': vref(recv['node_id'], acc['method_id'], recv.get('name',''), recv.get('code','')),
                'path': [],
            }
        base = receiver_location_for(inner, seen)
        _, inner_key = selector_for(inner)
        if inner_key is None:
            return base
        return {'root_ref': dict(base['root_ref']),
                'path': [dict(key) for key in base['path']] + [dict(inner_key)]}

    for cid, c in calls.items():
        if c['name'] != '<operator>.assignment':
            continue
        aa = args.get(cid, [])
        if len(aa) < 2:
            continue
        lhs, rhs = aa[0], aa[1]
        if lhs['node_id'] in accessors:
            acc = accessors[lhs['node_id']]
            recv, sel = selector_for(acc)
            if recv is not None and sel is not None:
                _rref = vref(recv['node_id'], c['method_id'], recv.get('name',''), recv.get('code',''))
                _rref, _via_block = rebound_receiver(cid, _rref, recv.get('name',''))
                _rloc = ({'root_ref': dict(_rref), 'path': []} if _via_block is not None
                         else receiver_location_for(acc))
                writes.append({
                    'function_id': c['method_id'], 'assignment_call_id': cid * 1000,
                    'accessor': 'INDEX' if acc['name'] == '<operator>.indexAccess' else 'FIELD',
                    'receiver': _receiver_ref(recv), 'key': sel,
                    'receiver_ref': _rref,
                    'receiver_location': _rloc,
                    'value_ref': vref(rhs['node_id'], c['method_id'], rhs.get('name',''), rhs.get('code','')),
                    'value': {'name': rhs['name'] or rhs['code'], 'type': rhs['type']},
                    'resolution': 'EXACT' if sel['kind'] == 'LITERAL' else 'AMBIGUOUS',
                    'code': c['code'],
                    'derivation': {
                        'origin': 'FRONTEND_COMPOSED',
                        'rule': 'ASSIGNMENT_TO_INDEX_ACCESS' if acc['name'] == '<operator>.indexAccess' else 'ASSIGNMENT_TO_FIELD_ACCESS',
                        'source_node_ids': [cid, acc['id'], lhs['node_id'], rhs['node_id']],
                    },
                })
                consumed_as_write_target.add(acc['id'])

    for cid, acc in accessors.items():
        if cid in consumed_as_write_target:
            continue
        recv, sel = selector_for(acc)
        if recv is not None and sel is not None:
            reads.append({
                'function_id': acc['method_id'], 'index_call_id': cid,
                'accessor': 'INDEX' if acc['name'] == '<operator>.indexAccess' else 'FIELD',
                'receiver': _receiver_ref(recv), 'key': sel,
                'receiver_ref': vref(recv['node_id'], acc['method_id'], recv.get('name',''), recv.get('code','')),
                'receiver_location': receiver_location_for(acc),
                'resolution': 'EXACT' if sel['kind'] == 'LITERAL' else 'AMBIGUOUS',
                'code': acc['code'],
                'derivation': {
                    'origin': 'FRONTEND_COMPOSED',
                    'rule': 'INDEX_ACCESS_READ' if acc['name'] == '<operator>.indexAccess' else 'FIELD_ACCESS_READ',
                    'source_node_ids': [cid],
                },
            })
    # SPREAD EXPANSION (FRONTEND_COMPOSED): <operator>.spread(_tmp, src) inside an
    # aliased block copies src's KNOWN literal slots (writes PRIOR to the spread)
    # into the alias target, strongly, in lowering order. Unknown pre-state slots
    # simply have no fact (reads of them abstain) - matching the Gate-22 truth.
    # Array-literal lowering uses _tmp.push(elem) per element and _tmp.push(...src)
    # for the spread. Prior single-element pushes both (a) occupy indices, shifting
    # the spread's slots, and (b) are themselves indexed writes. Multi-arg or
    # otherwise-shaped pushes disable expansion for that block (abstain, not guess).
    pushes_by_block = {}
    for pcid, pc in sorted(calls.items()):
        # MEASURED: jssrc2cpg emits array pushes with EMPTY name and
        # methodFullName '__ecma.Array:'; match on that + '.push(' in code.
        if not ((pc.get('mfn','') or '').startswith('__ecma.Array') and '.push(' in pc['code']):
            continue
        blocks_here = [b for b in call_blocks.get(pcid, ()) if b in block_alias]
        if not blocks_here:
            continue
        paa = [x for x in args.get(pcid, []) if x['index'] >= 1]
        pushes_by_block.setdefault(blocks_here[0], []).append((pcid, paa))
    _emitted_elements = set()
    for cid, c in sorted(calls.items()):
        if c['name'] != '<operator>.spread':
            continue
        aa = args.get(cid, [])
        if not aa:
            continue  # object lowering: (tmp, src); array lowering: (src) only
        # target = the block-aliased binding enclosing this spread (object AND array
        # lowerings differ in arg shape, but both sit inside the aliased block);
        # source = the argument that is not a lowering temp.
        tref = None
        for b in call_blocks.get(cid, ()):
            if b in block_alias:
                tref = block_alias[b][0]; break
        if tref is None:
            continue
        src_arg = next((x for x in aa if not (x.get('name','') or '').startswith('_tmp')), None)
        if src_arg is None:
            continue
        offset = 0
        if len(aa) == 1:  # array lowering: position among sibling pushes
            myblock = next((x for x in call_blocks.get(cid, ()) if x in block_alias), None)
            sibs = pushes_by_block.get(myblock, [])
            ok_shape = all(len(paa) == 1 for _, paa in sibs)
            if not ok_shape:
                continue  # unknown push shape: no expansion for this block
            prior = [(pcid, paa) for pcid, paa in sibs if paa[0]['node_id'] != cid and pcid < 
                     next((pcid2 for pcid2, paa2 in sibs if paa2[0]['node_id'] == cid), 1 << 62)]
            offset = len(prior)
            for i, (pcid, paa) in enumerate(sorted(prior)):
                # A block containing TWO spreads would re-emit the same prior push
                # element once per spread, producing duplicate write ids — which the
                # strict loader correctly REFUSED (p-limit, id ...234000). Emit each
                # (target, push) element exactly once.
                if (id(tref), pcid) in _emitted_elements:
                    continue
                _emitted_elements.add((id(tref), pcid))
                el = paa[0]
                writes.append({
                    'function_id': c['method_id'], 'assignment_call_id': pcid * 1000,
                    'accessor': 'INDEX', 'receiver': {'name': '', 'type': ''},
                    'key': {'kind': 'LITERAL', 'value': str(i)},
                    'receiver_ref': tref,
                    'receiver_location': {'root_ref': dict(tref), 'path': []},
                    'value_ref': vref(el['node_id'], c['method_id'], el.get('name',''), el.get('code','')),
                    'value': {'name': el.get('name') or el.get('code',''), 'type': el.get('type','')},
                    'resolution': 'EXACT', 'code': 'push-element',
                    'derivation': {'origin': 'FRONTEND_COMPOSED', 'rule': 'ARRAY_LITERAL_ELEMENT',
                                   'source_node_ids': [pcid, el['node_id']]},
                })
        sref = vref(src_arg['node_id'], c['method_id'], src_arg.get('name',''), src_arg.get('code',''))
        expanded = 0
        for w in list(writes):
            if w['function_id'] != c['method_id']:
                continue
            if w['receiver_ref'] != sref:
                continue
            # DYNAMIC prior writes transfer as pollution: dropping them would
            # harden reads of the copy (measured on objectSpreadDynamicWrite).
            if w['assignment_call_id'] >= cid * 1000:
                continue  # only writes PRIOR to the spread
            expanded += 1
            writes.append({
                'function_id': c['method_id'],
                'assignment_call_id': cid * 1000 + expanded,
                'accessor': w['accessor'], 'receiver': dict(w['receiver']),
                'key': ({'kind': 'LITERAL', 'value': str(int(w['key']['value']) + offset)}
                        if offset and w['key']['kind'] == 'LITERAL' and str(w['key']['value']).isdigit()
                        else dict(w['key'])),
                'receiver_ref': tref, 'value_ref': dict(w['value_ref']),
                'receiver_location': {'root_ref': dict(tref), 'path': []},
                'value': dict(w['value']),
                'resolution': w['resolution'], 'code': 'spread:' + c['code'],
                'derivation': {'origin': 'FRONTEND_COMPOSED', 'rule': 'SPREAD_EXPANSION',
                               'source_node_ids': [cid, w['assignment_call_id'] // 1000]},
            })
    return {'schema': 'portable-state-facts/0.4', 'state_writes': writes, 'state_reads': reads}

if __name__ == '__main__':
    out = derive(sys.argv[1])
    dest = sys.argv[2] if len(sys.argv) > 2 else None
    s = json.dumps(out, indent=2, sort_keys=True)
    if dest: Path(dest).write_text(s + '\n')
    else: print(s)
