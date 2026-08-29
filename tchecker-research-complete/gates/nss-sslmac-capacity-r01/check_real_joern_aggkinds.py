#!/usr/bin/env python3
"""REAL-JOERN-AGGKINDS-R01: the one gate in this suite whose raw facts are not
hand-built. `raw_real_joern_aggkinds/` is FROZEN output from an actual
`c2cpg.sh` + `export_c_cpp_facts_v03.sc` run (Joern v4.0.608, pinned by
`tchecker-research-complete/bootstrap.sh`) against `fixture_source.cpp` in
that directory, generated once in an environment with real Joern installed
and checked in so this gate reproduces without needing Joern again.

This is what the rest of the suite in this directory (`build_and_check.py`,
24/24) cannot be: those fixtures hand-build raw TSVs to stand in for what the
exporter *would* emit, which tests the normalizer's CONSUMPTION of
`aggregate_kinds.tsv` but never the exporter's PRODUCTION of it. This gate
runs the real normalizer (subprocess, no shortcuts) over real c2cpg output
and checks the two things only a real CPG can answer: what `TypeDecl.code`
actually looks like for each aggregate shape, and whether the exporter's
classification of it survives all the way through to dest-capacity facts.

Regenerating the frozen raw facts (only needed if `fixture_source.cpp` or
the exporter's *emitted columns* change -- the classification LOGIC is
exercised directly by re-running the checks below against the existing
frozen facts):
    export JOERN_HOME=/path/to/joern-cli   # pinned version: see bootstrap.sh
    "$JOERN_HOME/c2cpg.sh" -o /tmp/aggkinds.cpg.bin fixture_source.cpp
    "$JOERN_HOME/joern" --script ../../portable-engine-full-review-package/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc \
        --param cpgFile=/tmp/aggkinds.cpg.bin --param outDir=raw_real_joern_aggkinds
    (then restore fixture_source.cpp, which the exporter does not touch)
"""
import json, pathlib, subprocess, sys, base64

HERE = pathlib.Path(__file__).parent
FRONTEND = HERE / '../../portable-engine-full-review-package/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py'
RAW = HERE / 'raw_real_joern_aggkinds'

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(('PASS' if cond else 'FAIL'), name)


def dec(b):
    return base64.b64decode(b).decode('utf-8', 'replace') if b else ''


# --- 0. Sanity: the frozen raw facts really do carry the aggregate-kind
# rows this gate depends on, and they say what the README claims real Joern
# says (struct/class/anonymous classify from their own code text; a
# *named* union classifies too -- the alias fix is checked structurally
# below via the actual dest-capacity/fieldcapclass behavior, since that is
# the property that actually matters).
type_decl_names = {}
for ln in (RAW / 'type_decls.tsv').read_text().splitlines():
    if not ln.strip():
        continue
    xs = ln.split('\t')
    type_decl_names[xs[0]] = dec(xs[1])

agg_kinds = {}
for ln in (RAW / 'aggregate_kinds.tsv').read_text().splitlines():
    if not ln.strip():
        continue
    xs = ln.split('\t')
    agg_kinds[xs[0]] = dec(xs[1])

named_struct_id = next(k for k, v in type_decl_names.items() if v == 'NamedStruct')
named_union_id = next(k for k, v in type_decl_names.items() if v == 'NamedUnion')
named_class_id = next(k for k, v in type_decl_names.items() if v == 'NamedClass')
struct_alias_id = next(k for k, v in type_decl_names.items() if v == 'StructAlias')
union_alias_id = next(k for k, v in type_decl_names.items() if v == 'UnionAlias')

ck('real Joern: NamedStruct classified STRUCT', agg_kinds.get(named_struct_id) == 'STRUCT')
ck('real Joern: NamedUnion classified UNION', agg_kinds.get(named_union_id) == 'UNION')
ck('real Joern: NamedClass classified CLASS', agg_kinds.get(named_class_id) == 'CLASS')
ck('real Joern: StructAlias (typedef) classified STRUCT via aliasTypeFullName resolution',
   agg_kinds.get(struct_alias_id) == 'STRUCT')
ck('real Joern: UnionAlias (typedef) classified UNION via aliasTypeFullName resolution',
   agg_kinds.get(union_alias_id) == 'UNION')

# --- 1. Run the REAL normalizer over the real raw facts.
outpath = HERE / 'out_real_joern_aggkinds.json'
subprocess.run([sys.executable, str(FRONTEND), str(RAW), str(outpath)], check=True)
destcap = json.loads((HERE / (outpath.name + '.destcapacity.json')).read_text())['dest_capacities']
fieldcls = json.loads((HERE / (outpath.name + '.fieldcapclass.json')).read_text())['classification']

methods = {}
for ln in (RAW / 'methods.tsv').read_text().splitlines():
    if not ln.strip():
        continue
    xs = ln.split('\t')
    methods[xs[0]] = dec(xs[1])
by_fn = {methods.get(str(f['function_id']), '?'): f for f in destcap}

# --- 2. Struct member (bare access via memcpy dest): full capacity, no offset shape.
f = by_fn.get('copyStructBare')
ck('copyStructBare: emitted', f is not None)
ck('copyStructBare: capacity_bytes == 256', f and f['capacity_bytes'] == 256)
ck('copyStructBare: rule == CPP_STRUCT_MEMBER_ARRAY_CAPACITY',
   f and f['derivation']['rule'] == 'CPP_STRUCT_MEMBER_ARRAY_CAPACITY')
ck('copyStructBare: offset_shape explicitly False', f and f['offset_shape'] is False and f['offset_expr'] is None)

# --- 3. Struct member, `obj->buffer + off` shape.
f = by_fn.get('copyStructOffset')
ck('copyStructOffset (`+off` shape): emitted, capacity 256', f and f['capacity_bytes'] == 256)
ck('copyStructOffset: offset_shape=True, offset_expr="off" retained verbatim',
   f and f['offset_shape'] is True and f['offset_expr'] == 'off')
ck('copyStructOffset: rule == CPP_STRUCT_MEMBER_OFFSET_ARRAY_CAPACITY (open candidate, not a narrowed bound)',
   f and f['derivation']['rule'] == 'CPP_STRUCT_MEMBER_OFFSET_ARRAY_CAPACITY')

# --- 4. Struct member, `&obj->buffer[off]` shape.
f = by_fn.get('copyStructIndexOffset')
ck('copyStructIndexOffset (`&x[off]` shape): emitted, capacity 256', f and f['capacity_bytes'] == 256)
ck('copyStructIndexOffset: offset_shape=True, offset_expr="off" retained verbatim',
   f and f['offset_shape'] is True and f['offset_expr'] == 'off')

# --- 5. Class member (bare): same treatment as struct.
f = by_fn.get('copyClassBare')
ck('copyClassBare: capacity_bytes == 256', f and f['capacity_bytes'] == 256)
ck('copyClassBare: rule == CPP_STRUCT_MEMBER_ARRAY_CAPACITY', f and f['derivation']['rule'] == 'CPP_STRUCT_MEMBER_ARRAY_CAPACITY')

# --- 6. Struct member reached via its typedef alias: still resolves to 256.
# (This never actually depended on the alias's OWN classification -- only
# union membership blocks resolution -- but is checked directly here rather
# than assumed.)
f = by_fn.get('copyViaStructAlias')
ck('copyViaStructAlias: capacity_bytes == 256 (typedef alias does not block struct resolution)',
   f and f['capacity_bytes'] == 256)

# --- 7. THE FIX: union member, bare access, through the NAMED union type
# directly (no alias involved at the call site at all). Before the
# aliasTypeFullName fix, this fabricated a capacity fact anyway, because
# UnionAlias's TypeDecl existed elsewhere in the same translation unit and,
# being left UNKNOWN by the text heuristic, silently overwrote the real
# union's classification for the shared member id in the normalizer's
# id-keyed member lookup. Must be ABSENT from dest_capacities.
ck('copyUnionBare: NO capacity fabricated (fail-closed, alias-shadowing bug fixed)',
   'copyUnionBare' not in by_fn)

# --- 8. THE FIX, offset-shape path: union member via `&u->buffer[off]`.
ck('copyUnionOffset: NO capacity fabricated through the offset-shape path either',
   'copyUnionOffset' not in by_fn)

# --- 9. THE FIX, via the alias itself: union member accessed through a
# UnionAlias*-typed pointer.
ck('copyViaUnionAlias: NO capacity fabricated when reached through the typedef alias',
   'copyViaUnionAlias' not in by_fn)

# --- 10. fieldcapclass counters corroborate: exactly 2 bare-access union
# hits recorded fail-closed (copyUnionBare, copyViaUnionAlias -- the offset
# path aborts earlier in `_offset_field_capacity` without incrementing this
# specific counter, checked structurally above instead).
ck('fieldcapclass: UNION_MEMBER_FAIL_CLOSED == 2', fieldcls.get('UNION_MEMBER_FAIL_CLOSED') == 2)
ck('fieldcapclass: CAPACITY_EMITTED == 3 (struct bare, class bare, struct-via-alias bare)',
   fieldcls.get('CAPACITY_EMITTED') == 3)
ck('fieldcapclass: OFFSET_FIELD_CAPACITY == 2 (both struct offset shapes; both union offset shapes abstained)',
   fieldcls.get('OFFSET_FIELD_CAPACITY') == 2)

# --- 11. No bound fact is ever fabricated for an offset shape (open
# candidate only, never a computed "capacity minus offset" claim).
boundpath = HERE / (outpath.name + '.bound.json')
if boundpath.exists():
    bounds = json.loads(boundpath.read_text()).get('bounds', [])
    ck('no BoundFact naming an offset-shaped capacity (offset shapes stay open candidates)',
       all(b.get('call_id') not in {f['call_id'] for f in destcap if f['offset_shape']} for b in bounds))

print(f'REAL_JOERN_AGGKINDS_R01={ok}/{total}')
sys.exit(0 if ok == total else 1)
