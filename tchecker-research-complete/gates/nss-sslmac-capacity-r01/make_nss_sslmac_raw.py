#!/usr/bin/env python3
"""Fixture builder for the struct-member fixed-array capacity model (NSS-R01 /
CAP-STRUCT-R01), following the same hand-crafted-raw-TSV convention as the
existing cpp-r06/tests/make_*_raw.py fixtures (no real Joern run — a
faithful, hand-built stand-in for what c2cpg emits for this shape).

Emits ONE raw-fact directory per scenario via `build()`. Each scenario models
a single (struct, member, memcpy-family call) shape as either the CONFIRMED
real NSS site or one adversarial control from the requested matrix:
pointer member, ambiguous member name across two structs, an arithmetic-macro
array dimension, and a flexible array member.

IDs are scenario-local and deliberately small; nothing here depends on any
other fixture's numbering.
"""
import base64, pathlib, sys


def b(s):
    return base64.b64encode((s or '').encode()).decode()


def write(outdir, name, rows):
    p = pathlib.Path(outdir) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('\n'.join('\t'.join(r) for r in rows) + ('\n' if rows else ''))


def build(outdir, *, struct_name, member_name, member_type_full_name,
          extra_members=None, copy_callee='PORT_Memcpy', extent_local_name='len',
          dest_shape='bare', is_union=False):
    """Build one fixture: a single function

        static CK_RV fn(SFTKObject *keyval, unsigned int extentLocalName) {
            StructName *obj;                       // local id 10, ptr to struct
            obj = (StructName *)PORT_Alloc(sizeof(StructName));
            <copy_callee>(DEST, keyval, extentLocalName);
        }

    where DEST depends on `dest_shape`:
      'bare'              -> obj->member
      'add_offset'        -> obj->member + off      (off: a second local param)
      'addr_index_offset' -> &obj->member[off]

    `obj->member`'s capacity is exactly what's under test. `keyval` (the
    READ_SRC operand) is left as a bare pointer parameter -- src-side
    resolution is not what this fixture matrix is validating. `is_union=True`
    marks the struct under test (type_decl id 1 -- never any `extra_members`
    struct) as a UNION via aggregate_kinds.tsv, for the fail-closed control.
    """
    outdir = pathlib.Path(outdir)
    extra_members = extra_members or {}

    write(outdir, 'meta.tsv', [[b('C'), b('synthetic-nss-r01'), b('/src')]])

    # --- type_decls: the struct under test (id 1), plus any extra struct(s)
    # the scenario needs (e.g. a second struct sharing the member NAME for the
    # ambiguous-member-name control).
    type_decls = [['1', b(struct_name), b(struct_name), b('fixture.c'), '1', 'false', '']]
    next_td = 2
    extra_type_ids = {}
    for extra_struct_name in extra_members:
        type_decls.append([str(next_td), b(extra_struct_name), b(extra_struct_name), b('fixture.c'), '1', 'false', ''])
        extra_type_ids[extra_struct_name] = next_td
        next_td += 1
    write(outdir, 'type_decls.tsv', type_decls)

    # --- members: the member under test, plus any same-named members on the
    # extra struct(s) (for the ambiguous-name control).
    members = [['100', '1', b(member_name), b(member_type_full_name), b(member_type_full_name), '2']]
    next_mid = 101
    for extra_struct_name, extra_type_full_name in extra_members.items():
        members.append([str(next_mid), str(extra_type_ids[extra_struct_name]), b(member_name),
                         b(extra_type_full_name), b(extra_type_full_name), '2'])
        next_mid += 1
    write(outdir, 'members.tsv', members)

    # --- UNION-R01: aggregate kind, only written when is_union is set. Absent
    # otherwise -- exercising the normalizer's backward-compatible default.
    if is_union:
        write(outdir, 'aggregate_kinds.tsv', [['1', b('UNION')]])

    # --- methods: one function, id 1000
    write(outdir, 'methods.tsv', [[
        '1000', b('fn'), b('fn:int(SFTKObject*,unsigned int)'), b('int(SFTKObject*,unsigned int)'),
        b('fixture.c'), '10', '20', b('METHOD'), b('<global>'), 'false']])
    params = [
        ['1', '1000', '1', b('keyval'), b('SFTKObject *keyval'), b('SFTKObject*'), '10'],
        ['2', '1000', '2', b(extent_local_name), b('unsigned int ' + extent_local_name), b('unsigned int'), '10'],
    ]
    if dest_shape != 'bare':
        params.append(['3', '1000', '3', b('off'), b('unsigned int off'), b('unsigned int'), '10'])
    write(outdir, 'parameters.tsv', params)
    write(outdir, 'method_returns.tsv', [['1900', '1000', b('CK_RV'), b('CK_RV'), '10']])

    # --- locals: `obj`, a pointer to the struct under test.
    write(outdir, 'locals.tsv', [['10', '1000', b('obj'), b('obj'), b(struct_name + ' *'), '12']])

    # --- calls: the alloc (id 200, uninterpreted -- its result is just
    # assigned to `obj`, not modeled as a capacity source), the fieldAccess
    # node (id 301: obj->member), an optional offset-wrapper node, and the
    # copy call under test (id 300).
    calls = [
        ['200', '1000', b('PORT_Alloc'), b('PORT_Alloc'), b('STATIC_DISPATCH'), b('void*'),
         b('PORT_Alloc(sizeof(' + struct_name + '))'), b('fixture.c'), '13', '', ''],
    ]
    field_code = 'obj->' + member_name
    calls.append(['301', '1000', b('<operator>.indirectFieldAccess'), b('<operator>.indirectFieldAccess'),
                  b('STATIC_DISPATCH'), b(member_type_full_name), b(field_code), b('fixture.c'), '14', '', ''])

    identifiers = [
        ['22', '1000', b('obj'), b('obj'), b(struct_name + ' *'), '14', '10'],
        ['20', '1000', b('keyval'), b('keyval'), b('SFTKObject*'), '14', '1'],
        ['21', '1000', b(extent_local_name), b(extent_local_name), b('unsigned int'), '14', '2'],
    ]
    arguments = [
        ['20', '300', '2', b('IDENTIFIER'), b('keyval'), b('keyval'), b('SFTKObject*'), '14'],
        ['21', '300', '3', b('IDENTIFIER'), b(extent_local_name), b(extent_local_name), b('unsigned int'), '14'],
        ['22', '301', '1', b('IDENTIFIER'), b('obj'), b('obj'), b(struct_name + ' *'), '14'],
        ['23', '301', '2', b('IDENTIFIER'), b(member_name), b(member_name), b(member_type_full_name), '14'],
    ]

    if dest_shape == 'bare':
        dest_id, dest_code, dest_type = '301', field_code, member_type_full_name
    elif dest_shape == 'add_offset':
        # <operator>.addition(fieldAccess(obj,member), off)  ==  obj->member + off
        dest_code = field_code + ' + off'
        calls.append(['302', '1000', b('<operator>.addition'), b('<operator>.addition'),
                      b('STATIC_DISPATCH'), b(member_type_full_name), b(dest_code), b('fixture.c'), '14', '', ''])
        arguments += [
            ['301', '302', '1', b('CALL'), b(field_code), b(''), b(member_type_full_name), '14'],
            ['24', '302', '2', b('IDENTIFIER'), b('off'), b('off'), b('unsigned int'), '14'],
        ]
        identifiers.append(['24', '1000', b('off'), b('off'), b('unsigned int'), '14', '3'])
        dest_id, dest_type = '302', member_type_full_name
    elif dest_shape == 'addr_index_offset':
        # <operator>.addressOf(indexAccess(fieldAccess(obj,member), off))  ==  &obj->member[off]
        index_code = field_code + '[off]'
        calls.append(['303', '1000', b('<operator>.indirectIndexAccess'), b('<operator>.indirectIndexAccess'),
                      b('STATIC_DISPATCH'), b(member_type_full_name), b(index_code), b('fixture.c'), '14', '', ''])
        calls.append(['304', '1000', b('<operator>.addressOf'), b('<operator>.addressOf'),
                      b('STATIC_DISPATCH'), b(member_type_full_name + '*'), b('&' + index_code),
                      b('fixture.c'), '14', '', ''])
        arguments += [
            ['301', '303', '1', b('CALL'), b(field_code), b(''), b(member_type_full_name), '14'],
            ['24', '303', '2', b('IDENTIFIER'), b('off'), b('off'), b('unsigned int'), '14'],
            ['303', '304', '1', b('CALL'), b(index_code), b(''), b(member_type_full_name), '14'],
        ]
        identifiers.append(['24', '1000', b('off'), b('off'), b('unsigned int'), '14', '3'])
        dest_id, dest_code, dest_type = '304', '&' + index_code, member_type_full_name + '*'
    else:
        raise ValueError('unknown dest_shape: %r' % dest_shape)

    calls.append(['300', '1000', b(copy_callee), b(copy_callee), b('STATIC_DISPATCH'), b('void'),
                  b('%s(%s, keyval, %s)' % (copy_callee, dest_code, extent_local_name)),
                  b('fixture.c'), '14', '', ''])
    arguments.insert(0, ['%s' % dest_id, '300', '1', b('CALL'), b(dest_code), b(''), b(dest_type), '14'])

    write(outdir, 'calls.tsv', calls)
    write(outdir, 'arguments.tsv', arguments)
    write(outdir, 'literals.tsv', [])
    write(outdir, 'identifiers.tsv', identifiers)
    write(outdir, 'returns.tsv', [])


if __name__ == '__main__':
    build(*sys.argv[1:])
