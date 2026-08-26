#!/usr/bin/env python3
"""Corrected dispatch-resolution classification for real jssrc2cpg facts.

Derived from measured Gate-24-TS observations (joern-cli v4.0.400), not assumptions:
  - concrete methods:   isExternal=false, fullName scoped like `file.ts::program:...`
  - linker artifacts:   isExternal=true — spelling variants (`:ts::` for `.ts::`),
                        `<init>`-scoped duplicates, union stubs (`A | B:process`),
                        bare interface/type-variable stubs (`Worker:process`, `T:process`),
                        member-scoped stubs (`Holder:<init>:<member>(worker):process`).

Rules (never harden a stub to EXACT):
  1. canonicalize spelling; collapse intermediate `:<init>:` scopes
  2. external candidate whose canonical name matches an internal method -> alias-merge
  3. union stub  -> expand parts to internal `<Type>:name` methods
  4. member stub -> resolve member's declared type via members facts, then as (3)
  5. bare-type stub -> internal same-named type decls' methods + implementor expansion
  6. internal interface method with implementors (via inheritsFrom) -> replace by impls
  7. classify: 0 mapped+0 stubs -> UNRESOLVED; 0 mapped+stubs -> HEURISTIC;
     1 mapped + no unmapped stubs + receiver-owner agreement -> EXACT;
     1 mapped otherwise -> HEURISTIC; >1 mapped -> AMBIGUOUS.
"""
import re

def canonical(name: str) -> str:
    # `01_exact_parameter:ts::program` -> `01_exact_parameter.ts::program` (also .js/.tsx/.jsx)
    return re.sub(r':(tsx?|jsx?)::', r'.\1::', name or '')

def collapse_init(name: str) -> str:
    # drop intermediate constructor scopes: `A:<init>:process` -> `A:process`
    # (a trailing `:<init>` — a constructor itself — is preserved)
    out = name
    while ':<init>:' in out:
        out = out.replace(':<init>:', ':')
    return out

_MEMBER = re.compile(r':<member>\(([^)]*)\):')

def is_dispatch_call(name, method_full_name=""):
    """True only for user-level method/function dispatch. Excludes Joern's lowering of
    syntax into CALL nodes (<operator>.*), intrinsics (<...>), and ECMA builtins
    (__ecma.*, *.factory). Measured on real jssrc2cpg v4.0.400: these are 1148/1410
    'calls' and carry no meaningful dispatch resolution."""
    n = (name or '').strip()
    if not n:
        return False
    if n.startswith('<'):            # <operator>.*, <returnValue>, <lambda>, etc.
        return False
    if n.startswith('__ecma') or n.startswith('__whatwg') or n.startswith('__typescript'):
        return False
    if n.endswith('.factory'):
        return False
    m = method_full_name or ''
    if m.startswith('<operator>') or m.startswith('__ecma'):
        return False
    return True


def raw_resolution(n_candidates):
    """The naive count-based resolution the frontends emit today."""
    return 'UNRESOLVED' if n_candidates == 0 else ('EXACT' if n_candidates == 1 else 'AMBIGUOUS')


def scope_narrow(call, methods_by_id, methods_by_full, enclosing_full, mapped, defs_count):
    """SHADOW-ONLY enclosing-scope narrowing for local-binding calls (measured before
    any promotion): eligible iff (a) the raw candidate set contains exactly ONE target
    whose fullName is `<enclosing>:<name>` (a lambda scoped inside the caller), and
    (b) the called binding has at most one definition in the caller. Returns
    (corrected_resolution, corrected_full_names, reason) or None when not applicable."""
    scoped = [m for m in mapped if m == f"{enclosing_full}:{call.get('name','')}"]
    if len(scoped) == 1 and defs_count <= 1 and len(mapped) > 1:
        return ('EXACT', scoped, 'SCOPE_NARROWED_LOCAL_LAMBDA')
    return None

def classify_call_audit(call, methods_by_id, methods_by_full, type_decls, members):
    """Full shadow audit record. Does not mutate inputs; emits raw + corrected + why.

    Returns a dict:
      resolution_raw, resolution_corrected, resolution_reason,
      canonical_targets, concrete_targets, stub_targets,
      receiver_type, receiver_owner_match
    """
    corrected, mapped, reasons = classify_call(call, methods_by_id, methods_by_full, type_decls, members)
    tids = call.get('candidate_target_ids', [])
    raw = raw_resolution(len(tids))

    # Finding A: operator/intrinsic pseudo-calls carry no dispatch resolution.
    if not is_dispatch_call(call.get('name'), call.get('method_full_name')):
        return {
            'resolution_raw': raw,
            'resolution_corrected': 'NOT_DISPATCH',
            'resolution_reason': 'NOT_DISPATCH_CALL',
            'canonical_targets': [], 'concrete_targets': [], 'stub_targets': [],
            'corrected_targets': [], 'receiver_type': None, 'receiver_owner_match': False,
            'audit_reasons': ['operator/intrinsic call excluded from resolution'],
        }

    internal_full = set(methods_by_full.keys())
    concrete_targets, stub_targets, canonical_targets = [], [], []
    for cid in tids:
        meta = methods_by_id.get(cid)
        if meta is None:
            stub_targets.append(str(cid)); continue
        canon = collapse_init(canonical(meta['full_name']))
        canonical_targets.append(canon)
        if not meta['is_external'] and '::program' in canon:
            concrete_targets.append(canon)
        else:
            stub_targets.append(meta['full_name'])
    # Finding C: concrete targets also include methods recovered by alias-merge/expansion,
    # i.e. anything in `mapped` that is an internal method, not just isExternal=false candidates.
    for t in mapped:
        if t in internal_full:
            concrete_targets.append(t)

    # receiver type + owner-agreement (mirrors classify_call's EXACT precondition)
    receiver = None
    declared = call.get('receiver_declared_type')
    if declared:
        r = collapse_init(canonical(declared))
        receiver = r[:-len(':<init>')] if r.endswith(':<init>') else r
    else:
        args = sorted(call.get('arguments', []), key=lambda a: a['index'])
        if args:
            r = collapse_init(canonical(args[0].get('type_full_name') or ''))
            receiver = r[:-len(':<init>')] if r.endswith(':<init>') else r
    # a union-typed receiver can never strict- or weak-match a single owner
    _union_receiver = receiver is not None and ' | ' in receiver
    receiver_owner_match = (not _union_receiver) and bool(mapped) and len(mapped) == 1 and receiver == mapped[0].rsplit(':', 1)[0]

    # ids of the corrected concrete targets (for arity-consistent promotion downstream)
    full_to_id = {}
    for cid, meta in methods_by_id.items():
        c = collapse_init(canonical(meta['full_name']))
        full_to_id.setdefault(c, cid)
    corrected_ids = [full_to_id[t] for t in mapped if t in full_to_id]

    reason = _reason_code(raw, corrected, mapped, stub_targets, reasons, receiver_owner_match)
    return {
        'resolution_raw': raw,
        'resolution_corrected': corrected,
        'resolution_reason': reason,
        'canonical_targets': sorted(set(canonical_targets)),
        'concrete_targets': sorted(set(concrete_targets)),
        'stub_targets': sorted(set(stub_targets)),
        'corrected_targets': mapped,
        'corrected_target_ids': corrected_ids,
        'receiver_type': receiver,
        'receiver_owner_match': receiver_owner_match,
        'audit_reasons': reasons,
    }


def _reason_code(raw, corrected, mapped, stub_targets, reasons, owner_match):
    joined = ' | '.join(reasons)
    if 'receiver-compatible (weak)' in joined:
        return 'DEDUP_CONCRETE_WEAK_RECEIVER'
    if raw == corrected and not stub_targets and 'alias' not in joined and 'interface' not in joined:
        return 'UNCHANGED'
    if 'union stub' in joined:
        return 'UNION_STUB_EXPANDED'
    if 'interface' in joined:
        return 'INTERFACE_MEMBER_EXPANDED'
    if 'member stub' in joined:
        return 'MEMBER_STUB_RESOLVED'
    if 'bare-type stub' in joined:
        return 'BARE_TYPE_STUB_EXPANDED'
    if corrected == 'EXACT' and 'receiver-compatible (weak)' in joined:
        return 'DEDUP_CONCRETE_WEAK_RECEIVER'
    if corrected == 'EXACT' and owner_match:
        return 'DEDUP_CONCRETE_RECEIVER_MATCH'
    if corrected == 'HEURISTIC' and 'unmappable stub' in joined:
        return 'UNMAPPABLE_STUB_NOT_HARDENED'
    if corrected == 'HEURISTIC' and 'receiver=' in joined:
        return 'SINGLE_TARGET_NO_RECEIVER_AGREEMENT'
    if raw == 'AMBIGUOUS' and corrected == 'EXACT':
        return 'DEDUP_CONCRETE_RECEIVER_MATCH'
    if corrected == 'UNRESOLVED':
        return 'NO_TARGETS'
    return 'UNCHANGED' if raw == corrected else 'RECLASSIFIED'


def classify_call(call, methods_by_id, methods_by_full, type_decls, members):
    """call: dict with candidate_target_ids, arguments (index+type_full_name).
    methods_by_id: id -> {full_name, is_external}; methods_by_full: canonical full -> id (internal only)
    type_decls: list of {name, full_name, inherits_from}; members: list of {owner_full, name, type}
    Returns (resolution, mapped_full_names_sorted, reasons)."""
    internal_types = {t['full_name']: t for t in type_decls if '::program' in t['full_name']}
    types_by_name = {}
    for t in internal_types.values():
        types_by_name.setdefault(t['name'], []).append(t['full_name'])
    impls_of = {}
    for t in internal_types.values():
        sup = t.get('inherits_from') or ''
        if sup and sup != 'ANY':
            impls_of.setdefault(canonical(sup), []).append(t['full_name'])
    member_type = {}
    for m in members:
        member_type[(canonical(m['owner_full']), m['name'])] = m['type']

    mapped, reasons, unmapped_stubs = set(), [], 0

    def methods_of_type(type_full, mname):
        out = set()
        cand = canonical(type_full) + ':' + mname
        if cand in methods_by_full:
            out.add(cand)
        for impl in impls_of.get(canonical(type_full), []):
            got = methods_of_type(impl, mname)
            out |= got
        return out

    for cid in call.get('candidate_target_ids', []):
        meta = methods_by_id.get(cid)
        if meta is None:
            unmapped_stubs += 1; reasons.append(f'id {cid} not in methods'); continue
        full = collapse_init(canonical(meta['full_name']))
        mname = full.rsplit(':', 1)[-1]
        if not meta['is_external']:
            if '::program' in full:
                # internal method; if it's an interface member with implementors, expand
                owner = full.rsplit(':', 1)[0]
                impl_methods = set()
                for impl in impls_of.get(owner, []):
                    impl_methods |= methods_of_type(impl, mname)
                if impl_methods:
                    mapped |= impl_methods
                    reasons.append(f'interface {full} -> {len(impl_methods)} implementor(s)')
                else:
                    mapped.add(full)
            else:
                unmapped_stubs += 1; reasons.append(f'internal-but-unscoped {full}')
            continue
        # external artifact
        if full in methods_by_full:
            mapped.add(full); reasons.append(f'alias {meta["full_name"]} -> {full}'); continue
        mm = _MEMBER.search(meta['full_name'])
        if mm:
            owner = collapse_init(canonical(meta['full_name'].split(':<member>')[0]))
            mt = member_type.get((owner, mm.group(1)))
            if mt:
                got = set()
                for tf in ([mt] if '::program' in mt else types_by_name.get(mt, [])):
                    got |= methods_of_type(tf, mname)
                if got:
                    mapped |= got; reasons.append(f'member stub -> {sorted(got)}'); continue
            unmapped_stubs += 1; reasons.append(f'member stub unresolved {meta["full_name"]}'); continue
        owner = full.rsplit(':', 1)[0]
        if ' | ' in owner:
            got = set()
            for part in owner.split(' | '):
                for tf in types_by_name.get(part.strip(), []):
                    got |= methods_of_type(tf, mname)
            if got:
                mapped |= got; reasons.append(f'union stub {owner} -> {len(got)} target(s)'); continue
            unmapped_stubs += 1; reasons.append(f'union stub unresolved {owner}'); continue
        if owner in types_by_name:
            got = set()
            for tf in types_by_name[owner]:
                got |= methods_of_type(tf, mname)
            if got:
                mapped |= got; reasons.append(f'bare-type stub {owner} -> {len(got)} target(s)'); continue
        unmapped_stubs += 1; reasons.append(f'unmappable stub {meta["full_name"]}')

    receiver = None
    declared = call.get('receiver_declared_type')
    if declared:
        r = collapse_init(canonical(declared))
        receiver = r[:-len(':<init>')] if r.endswith(':<init>') else r
    else:
        args = sorted(call.get('arguments', []), key=lambda a: a['index'])
        if args:
            r = collapse_init(canonical(args[0].get('type_full_name') or ''))
            receiver = r[:-len(':<init>')] if r.endswith(':<init>') else r
    union_members = None
    if receiver is not None and ' | ' in receiver:
        union_members = [m.strip() for m in receiver.split(' | ')]
        receiver = '<union>:' + receiver   # sentinel: never equals an owner, never ANY-compatible

    # UNION-RECEIVER EXPANSION (activates only when a union receiver survives to
    # here, i.e. via the tsc sidecar — jssrc2cpg alone never delivers one; measured):
    # expand to the members' same-named methods. >=2 resolved members = AMBIGUOUS
    # over them, never EXACT; <2 = no expansion (fall through unchanged).
    if union_members is not None:
        expanded = []
        cname = call.get('name', '')
        for m in union_members:
            fq = canonical(m) + ':' + cname
            if fq in methods_by_full:
                expanded.append(fq)
        if len(expanded) >= 2:
            return 'AMBIGUOUS', sorted(set(expanded)), ['union receiver expanded: ' + ' | '.join(union_members)]

    if not mapped and unmapped_stubs == 0:
        res = 'UNRESOLVED'
    elif not mapped:
        res = 'HEURISTIC'
    elif len(mapped) == 1:
        only = next(iter(mapped)); owner = only.rsplit(':', 1)[0]
        if unmapped_stubs == 0 and receiver == owner:
            res = 'EXACT'
        elif unmapped_stubs == 0 and _receiver_compatible(receiver, owner):
            # Finding B: real jssrc2cpg frequently types the receiver as ANY or a bare
            # unscoped class name. With exactly one concrete same-named target and no
            # stubs, there is no competing implementation to lose, so this is EXACT.
            # Marked with a distinct reason so its blast radius stays measurable.
            res = 'EXACT'
            reasons.append(f'receiver-compatible (weak): receiver={receiver!r} owner={owner!r}')
        else:
            res = 'HEURISTIC'
            reasons.append(f'single target but receiver={receiver!r} vs owner={owner!r}, stubs={unmapped_stubs}')
    else:
        res = 'AMBIGUOUS'
    return res, sorted(mapped), reasons


def _receiver_compatible(receiver, owner):
    """Weak receiver agreement for the measured ANY/bare-name cases.
    owner is like 'file.ts::program:A'. Accept when:
      - receiver is missing/ANY (jssrc2cpg lost the type), or
      - receiver is the bare class name matching owner's last class segment.
    Caller guarantees exactly one concrete target and zero stubs, so accepting
    ANY cannot merge away a competing implementation."""
    if receiver is not None and receiver.startswith('<union>:'):
        return False
    if receiver in (None, '', 'ANY', 'any'):
        return True
    owner_class = owner.rsplit(':', 1)[-1]
    return receiver == owner_class
