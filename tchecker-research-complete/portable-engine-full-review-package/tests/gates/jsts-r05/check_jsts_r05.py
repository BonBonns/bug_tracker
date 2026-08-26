import re, sys
out = open(sys.argv[1]).read()
def summary(name):
    m = re.search(r'^SUMMARY ' + name + r' resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+) completeness=(\S+)', out, re.M)
    if not m: return None
    pos = lambda s: [int(x) for x in s.split(',') if x.strip()]
    return {'res': m.group(1), 'proven': pos(m.group(2)), 'may': pos(m.group(3)),
            'unknown': m.group(4) == 'true', 'comp': m.group(5)}
def evid(name):
    m = re.search(r'^EVIDENCE ' + name + r' identity=(\S+) origin=(\S+) resolution=(\S+) completeness=(\S+)', out, re.M)
    return m.groups() if m else None
checks = []
def ck(n, ok, d=''):
    checks.append(bool(ok)); print(('PASS' if ok else 'FAIL'), n, ('- ' + str(d) if d else ''))

ck('pipeline completed', 'ANALYSIS_STATUS=COMPLETE' in out)
ck('loader accepted schema', 'LOADED frontend=joern-jssrc2cpg' in out)
h = summary('helper')
ck('helper: EXACT proven=[0] (return value)', h and h['res'] == 'EXACT' and h['proven'] == [0] and h['comp'] == 'COMPLETE', h)
m = summary('main')
ck('main: EXACT proven=[0] THROUGH the real call graph (input -> helper -> return)', m and m['res'] == 'EXACT' and m['proven'] == [0] and m['comp'] == 'COMPLETE', m)
c = summary('constant')
ck('constant: no provenance, COMPLETE (demonstrated no-origin, not UNKNOWN)', c and c['proven'] == [] and c['may'] == [] and not c['unknown'] and c['comp'] == 'COMPLETE', c)
p = summary('passthrough')
ck('passthrough: EXACT proven=[1] (b, not a)', p and p['res'] == 'EXACT' and p['proven'] == [1], p)
he = evid('helper')
ck('helper evidence: VALUE_SPECIFIC ESTABLISHED EXACT COMPLETE', he == ('VALUE_SPECIFIC', 'ESTABLISHED', 'EXACT', 'COMPLETE'), he)
ce = evid('constant')
ck('constant evidence: originStatus NONE (complete no-origin, not NOT_ESTABLISHED)', ce and ce[1] == 'NONE', ce)
ok = sum(checks)
print(f'JSTS_R05={ok}/{len(checks)}')
sys.exit(0 if ok == len(checks) else 1)
