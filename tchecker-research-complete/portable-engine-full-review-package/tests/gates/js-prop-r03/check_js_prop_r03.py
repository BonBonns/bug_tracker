#!/usr/bin/env python3
"""JS-PROP-R03: frontend path identity plus end-to-end semantic teeth."""
import json
import re
import sys

program = json.load(open(sys.argv[1]))
state = json.load(open(sys.argv[2]))
engine = open(sys.argv[3]).read()
functions = {f['name']: f for f in program['functions'] if not f.get('is_external')}
reads = {r['index_call_id']: r for r in state['state_reads']}
writes_by_fid = {}
for write in state['state_writes']:
    writes_by_fid.setdefault(write['function_id'], []).append(write)
returns_by_fid = {}
for ret in program['returns']:
    returns_by_fid.setdefault(ret['function_id'], []).append(ret)

checks = []
def ck(name, condition, detail=''):
    checks.append(bool(condition))
    print(('PASS ' if condition else 'FAIL ') + name + ('' if condition else ' - ' + str(detail)))

def returned_read(name):
    fid = functions[name]['id']
    ret = next(r for r in returns_by_fid[fid] if r.get('value_ref', {}).get('kind') == 'STATE_READ')
    return reads[ret['value_ref']['id']]

def path(location):
    return [(k['kind'], k.get('value') if k['kind'] == 'LITERAL' else k.get('ref'))
            for k in location['path']]

def summary(name):
    match = re.search(r'^SUMMARY ' + re.escape(name)
        + r' resolution=(\S+) proven=\[([^]]*)\] may=\[([^]]*)\] unknown=(\S+)',
        engine, re.MULTILINE)
    if not match:
        return None
    nums = lambda s: [int(x.strip()) for x in s.split(',') if x.strip()]
    return {'resolution': match.group(1), 'proven': nums(match.group(2)),
            'may': nums(match.group(3)), 'unknown': match.group(4)}

ck('schema 0.4 makes canonical location mandatory', state.get('schema') == 'portable-state-facts/0.4', state.get('schema'))

positive = returned_read('nestedPositive')
ck('nested positive root is the input PARAMETER', positive['receiver_location']['root_ref']['kind'] == 'PARAMETER', positive)
ck('nested positive receiver path is literal profile', path(positive['receiver_location']) == [('LITERAL', 'profile')], positive)

same = returned_read('samePathOverwrite')
same_write = next(w for w in writes_by_fid[functions['samePathOverwrite']['id']] if 'profile.url' in w['code'])
ck('separate read/write AST nodes have different raw receiver ids',
   same['receiver_ref']['id'] != same_write['receiver_ref']['id'], (same['receiver_ref'], same_write['receiver_ref']))
ck('same-path read/write canonical receiver locations are equal',
   same['receiver_location'] == same_write['receiver_location'], (same['receiver_location'], same_write['receiver_location']))

parent_read = returned_read('parentOverwrite')
parent_write = next(w for w in writes_by_fid[functions['parentOverwrite']['id']] if 'input.profile =' in w['code'])
ck('parent overwrite is represented as root + profile key',
   path(parent_write['receiver_location']) == [] and parent_write['key'].get('value') == 'profile'
   and path(parent_read['receiver_location']) == [('LITERAL', 'profile')], (parent_read, parent_write))

distinct = returned_read('distinctRoot')
distinct_write = next(iter(writes_by_fid[functions['distinctRoot']['id']]))
ck('same property path on distinct bindings keeps distinct roots',
   distinct['receiver_location']['root_ref']['id'] != distinct_write['receiver_location']['root_ref']['id'],
   (distinct['receiver_location'], distinct_write['receiver_location']))

dynamic = returned_read('dynamicPath')
ck('dynamic receiver selector remains explicit and non-propagatable',
   path(dynamic['receiver_location']) == [('DYNAMIC', 'key')], dynamic)

expect = {
    'nestedPositive': ('AMBIGUOUS', [], [0]),
    'samePathOverwrite': ('EXACT', [1], []),
    'parentOverwrite': ('UNRESOLVED', [], []),
    'distinctRoot': ('AMBIGUOUS', [], [0]),
    'dynamicPath': ('UNRESOLVED', [], []),
    'siblingWrite': ('UNRESOLVED', [], []),
    'localPositive': ('AMBIGUOUS', [], [0]),
    'childThenParent': ('UNRESOLVED', [], []),
}
for name, wanted in expect.items():
    got = summary(name)
    ck(f'end-to-end {name} => {wanted}', got is not None and
       (got['resolution'], got['proven'], got['may']) == wanted, got)

print(f'JS_PROP_R03={sum(checks)}/{len(checks)}')
sys.exit(0 if all(checks) else 1)
