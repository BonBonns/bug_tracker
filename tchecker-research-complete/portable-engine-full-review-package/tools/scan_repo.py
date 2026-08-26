#!/usr/bin/env python3
"""Repo scanner: run the full portable-provenance pipeline against a real
repository and report per-function results PLUS a measured abstention taxonomy.

The taxonomy is the point: every abstaining function is classified by the ACTUAL
fact shape that stopped it (which operator, external call, variable index,
multi-def, ...), read from the normalized documents — never guessed from source.
Aggregated across repositories, the taxonomy tells us what the next frontend
milestone (e.g. CPP-R03) should contain, ranked by measured frequency.

usage: scan_repo.py TARGET [--lang c|js|auto] [--out report.json] [--work DIR]
  TARGET: a local path or a git URL (shallow-cloned)
env: JOERN_HOME (joern-cli with c2cpg.sh / jssrc2cpg.sh), and the package root
     is inferred from this script's location.
"""
import argparse, json, os, pathlib, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
JH = pathlib.Path(os.environ.get('JOERN_HOME', ''))
C_EXT = {'.c', '.cc', '.cpp', '.cxx'}
H_EXT = {'.h', '.hpp', '.hh'}
JS_EXT = {'.js', '.mjs', '.ts'}
SKIP_DIRS = {'node_modules', 'test', 'tests', 'examples', 'deps', 'third_party', 'vendor', '.git', 'build', 'dist'}

def run(cmd, log, cwd=None):
    with open(log, 'a') as lf:
        r = subprocess.run(cmd, cwd=cwd, stdout=lf, stderr=lf)
    if r.returncode != 0:
        raise SystemExit(f'FAILED ({r.returncode}): {" ".join(map(str, cmd))} — see {log}')

def collect(repo, exts, cap=40):
    out = []
    for p in sorted(repo.rglob('*')):
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts): continue
        if p.suffix in exts and p.is_file():
            out.append(p)
            if cap is not None and len(out) >= cap: break
    return out

def stage(files, dst, repo):
    """Stage without flattening paths (flat staging silently overwrote namesakes)."""
    dst.mkdir(parents=True, exist_ok=True)
    for f in files:
        target = dst / f.relative_to(repo)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(f, target)

def selection_group(repo, exts, selected, cap):
    discovered = [p for p in repo.rglob('*') if p.is_file() and p.suffix in exts]
    eligible = [p for p in discovered if not any(part in SKIP_DIRS for part in p.relative_to(repo).parts)]
    return {
        'extensions': sorted(exts), 'cap': cap,
        'discovered': len(discovered), 'excluded_by_directory_policy': len(discovered) - len(eligible),
        'eligible': len(eligible), 'selected': len(selected), 'omitted_by_cap': len(eligible) - len(selected),
        'selected_paths': [str(p.relative_to(repo)).replace('\\', '/') for p in selected],
    }

def preprocessed_target(repo, source, dst):
    """Unique, relative-path-preserving C filename for a preprocessed TU."""
    rel = source.relative_to(repo)
    return dst / rel.parent / (rel.name + '.preprocessed.c')

def parse_summaries(text):
    out = {}
    for name, summary in parse_summary_stream(text):
        out.setdefault(name, []).append(summary)
    return out

def parse_summary_stream(text):
    """Return summaries in engine emission order; names are not identities."""
    out = []
    for m in re.finditer(r'SUMMARY (\S+) resolution=(\S+) proven=\[([^\]]*)\] may=\[([^\]]*)\] unknown=(\S+) completeness=(\S+)', text):
        nums = lambda s: [int(x) for x in s.split(',') if x.strip()]
        out.append((m.group(1), {
            'resolution': m.group(2), 'proven': nums(m.group(3)), 'may': nums(m.group(4)),
            'unknown': m.group(5) == 'true', 'completeness': m.group(6)}))
    return out

def bind_summaries_to_functions(text, functions):
    """Bind by the runner's preserved function order, validating every name.

    EndToEndRunner historically printed only the bare name.  Real repositories
    contain hundreds of same-named methods/lambdas, so looking up `sums[name][0]`
    silently attached the first function's result to every namesake.
    """
    emitted = [f for f in functions
               if not f.get('is_external') and f.get('name')
               and f['name'] != ':program' and not f['name'].startswith('<operator>')]
    stream = parse_summary_stream(text)
    if len(stream) != len(emitted):
        raise ValueError(f'summary/function count mismatch: summaries={len(stream)} functions={len(emitted)}')
    out = {}
    for index, (f, (name, summary)) in enumerate(zip(emitted, stream)):
        if name != f['name']:
            raise ValueError(f'summary/function order mismatch at {index}: summary={name} function={f["name"]}')
        out[f['id']] = summary
    return out

def classify_abstention(fn, doc, calls_by_id, locals_defs, reaching=None):
    """MEASURED classification: read the fact shape that stopped the flow."""
    rets = [r for r in doc.get('returns', []) if r['function_id'] == fn['id']]
    if not rets:
        return 'NO_RETURN_FACT'
    reasons = set()
    for r in rets:
        vr = r['value_ref']; k = vr['kind']
        if k in ('PARAMETER', 'CONSTANT'):
            continue
        if k == 'CALL':
            c = calls_by_id.get(vr['id'])
            if c is None:
                reasons.add('RETURN_CALL_MISSING'); continue
            name = c.get('name', '')
            if name.startswith('<operator>'):
                # C++ emits bare '<operator>' names (no dot suffix) — measured on
                # leveldb, where the unguarded split crashed the scanner.
                reasons.add('OPERATOR:' + (name.split('.', 1)[1] if '.' in name else 'bare'))
            elif c.get('resolution') == 'EXACT':
                reasons.add('INTERNAL_CALLEE_ABSTAINED')
            elif any(t in {f['id'] for f in doc['functions'] if not f.get('is_external')}
                     for t in c.get('candidate_target_ids', [])):
                # DISPATCH-R01: the callee IS in-repo; the engine simply declined to
                # treat a non-EXACT dispatch as proven. That is our own conservative
                # policy working, NOT an external/unknown symbol. Labelling it
                # EXTERNAL_OR_UNRESOLVED_CALL conflated 59 correct abstentions with
                # genuine external calls and made the class look like a feature gap.
                reasons.add('INTERNAL_NONEXACT_DISPATCH:' + (c.get('resolution') or '?'))
            else:
                reasons.add('EXTERNAL_OR_UNRESOLVED_CALL:' + (name or '?'))
        elif k == 'LOCAL':
            # The taxonomy must describe the CURRENT world: after reaching-def
            # narrowing, the live def count for THIS use is the narrowed one, not
            # the raw total. Classifying on the raw count would report a cause that
            # no longer exists.
            n = locals_defs.get(vr['id'], 0)
            if reaching is not None:
                rf = reaching.get(r['id'])
                if rf is not None and rf['local_id'] == vr['id']:
                    n = len(rf['def_ids'])
            if n == 0:
                # MEASURED (jsmn/linenoise/sds): zero-def locals split into two
                # distinct root causes — macro constants materialized as locals by
                # unpreprocessed c2cpg (NULL, EXIT_SUCCESS, ERROR_*), vs real
                # locals written only through &x out-params to external calls.
                lname = next((l['name'] for l in doc.get('locals', []) if l['id'] == vr['id']), '')
                reasons.add('UNDEFINED_IDENTIFIER(macro?)' if (lname.isupper() or lname == 'NULL')
                            else 'LOCAL_ONLY_OUTPARAM_OR_UNMODELED_WRITES')
            else:
                reasons.add('LOCAL_MULTI_DEF' if n > 1 else 'LOCAL_SINGLE_DEF_ABSTAINED')
        elif k == 'UNKNOWN':
            code = (vr.get('code') or r.get('code') or '').strip()
            if '->' in code: reasons.add('UNKNOWN_REF:pointer_member')
            elif code.startswith('*'): reasons.add('UNKNOWN_REF:deref')
            elif '[' in code: reasons.add('UNKNOWN_REF:index')
            elif re.search(r'[-+*/%&|^]| \? ', code): reasons.add('UNKNOWN_REF:expression')
            elif re.match(r'\(\s*\w[\w :*&<>]*\)\s*', code): reasons.add('UNKNOWN_REF:cast')
            else: reasons.add('UNKNOWN_REF:other')
        else:
            reasons.add('REF_KIND:' + k)
    return '+'.join(sorted(reasons)) if reasons else 'UNCLASSIFIED'

def preprocess_c(repo, files, dst, log):
    """PREPROCESSED-SOURCE MODE (the measured #1 blocker: c2cpg parses raw sources,
    so NULL/EXIT_SUCCESS/JSMN_ERROR_* appear as write-less locals and function-like
    macros like SDS_HDR appear as unresolved calls). Running the real preprocessor
    first is the honest fix — it resolves macros by DEFINITION rather than by
    name-guessing. Preprocessed units keep a .c name so c2cpg treats them normally.
    Files that fail to preprocess are SKIPPED (reported), never silently patched."""
    dst.mkdir(parents=True, exist_ok=True)
    incs = sorted({str(f.parent) for f in files} | {str(repo), str(repo / 'src'), str(repo / 'include')})
    inc_args = []
    for i in incs:
        if pathlib.Path(i).is_dir(): inc_args += ['-I', i]
    ok, failed = 0, []
    for f in files:
        if f.suffix not in C_EXT: continue
        out = preprocessed_target(repo, f, dst)
        out.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(['gcc', '-E', '-P'] + inc_args + [str(f), '-o', str(out)],
                           capture_output=True, text=True)
        if r.returncode == 0 and out.exists() and out.stat().st_size > 0:
            ok += 1
        else:
            failed.append(f.name)
            out.unlink(missing_ok=True)
    with open(log, 'a') as lf:
        lf.write(f'preprocess: {ok} ok, {len(failed)} failed: {failed}\n')
    print(f'  preprocessed {ok} translation unit(s)' + (f'; SKIPPED {len(failed)}: {failed}' if failed else ''))
    return ok > 0

def scan_c_build_aware(repo, work, log, ccj_path):
    """BUILD-AWARE mode: drive c2cpg from a real compile_commands.json so the
    frontend sees the SAME program the compiler sees — real include paths, real
    -D macros, real per-translation-unit scope. Flat staging (the default mode)
    was measured to leave 186/400 unresolved C++ calls with NO definition present
    in the CPG at all, because files and generated headers outside the staged set
    are simply absent. This addresses the CORPUS method, not the analysis.
    Each TU is preprocessed with its OWN recorded flags, then handed to c2cpg."""
    entries = json.load(open(ccj_path))
    src = work / 'csrc'; src.mkdir(parents=True, exist_ok=True)
    ok, failed = 0, []
    for e in entries:
        f = pathlib.Path(e['file'])
        if f.suffix not in (C_EXT | {'.cxx'}): continue
        cmd = e.get('command') or ' '.join(e.get('arguments', []))
        import shlex
        toks = shlex.split(cmd)
        flags = []
        i = 1
        while i < len(toks):
            t = toks[i]
            if t.startswith(('-I', '-D', '-isystem', '-std=')):
                flags.append(t)
                if t in ('-I', '-D', '-isystem') and i + 1 < len(toks):
                    i += 1; flags.append(toks[i])
            i += 1
        out = src / (f.stem + '_' + str(ok) + '.cc')
        r = subprocess.run(['g++', '-E', '-P'] + flags + [str(f), '-o', str(out)],
                           capture_output=True, text=True, cwd=e.get('directory') or str(repo))
        if r.returncode == 0 and out.exists() and out.stat().st_size > 0:
            ok += 1
        else:
            failed.append(f.name); out.unlink(missing_ok=True)
    with open(log, 'a') as lf:
        lf.write(f'build-aware: {ok} TUs preprocessed, {len(failed)} failed: {failed}\n')
    print(f'  build-aware: {ok} translation unit(s) from compile_commands.json'
          + (f'; {len(failed)} failed' if failed else ''))
    return ok > 0

def scan_c(repo, work, log, preprocess=False, ccj=None, impl_cap=40, header_cap=20):
    impl_files = collect(repo, C_EXT, cap=impl_cap)
    header_files = collect(repo, H_EXT, cap=header_cap)
    files = impl_files + header_files
    json.dump({'groups': {
        'implementations': selection_group(repo, C_EXT, impl_files, impl_cap),
        'headers': selection_group(repo, H_EXT, header_files, header_cap),
    }}, open(work / 'c.selection.json', 'w'), indent=1, sort_keys=True)
    if not files and not ccj: return None
    # header-only C libraries (e.g. jsmn.h) are still C: c2cpg parses headers.
    src = work / 'csrc'; raw = work / 'craw'; raw.mkdir(parents=True, exist_ok=True)
    if ccj:
        if not scan_c_build_aware(repo, work, log, ccj): return None
    elif preprocess:
        if not preprocess_c(repo, files, src, log): return None
    else:
        stage(files, src, repo)
    # Build-aware mode produces fully-preprocessed TUs (leveldb: 40MB), which
    # exceeded c2cpg's default heap. Raise it explicitly rather than silently
    # scanning less code.
    c2cpg_cmd = [JH / 'c2cpg.sh']
    if os.environ.get('C2CPG_HEAP'):
        c2cpg_cmd.append('-J-Xmx' + os.environ['C2CPG_HEAP'])
    run(c2cpg_cmd + ['-o', work / 'c.cpg', src], log)
    run([JH / 'joern', '--script', ROOT / 'tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc',
         '--param', f'cpgFile={work / "c.cpg"}', '--param', f'outDir={raw}'], log)
    run([sys.executable, ROOT / 'tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py', raw, work / 'cpp.json'], log)
    run([sys.executable, ROOT / 'tests/gates/cpp-r06/frontend/emit_reaching_defs.py',
         work / 'cpp.json', raw, str(work / 'cpp.json') + '.reachingdef.json'], log)
    return work / 'cpp.json'

def scan_js(repo, work, log, cap=40):
    files = collect(repo, JS_EXT, cap=cap)
    json.dump({'groups': {'sources': selection_group(repo, JS_EXT, files, cap)}},
              open(work / 'js.selection.json', 'w'), indent=1, sort_keys=True)
    if not files: return None
    src = work / 'jssrc'; raw = work / 'jsraw'; raw.mkdir(parents=True, exist_ok=True)
    stage(files, src, repo)
    run([JH / 'jssrc2cpg.sh', src, '--output', work / 'js.cpg.zip'], log)
    fr = ROOT / 'frontends/javascript-typescript/joern-ts'
    run([JH / 'joern', '--script', fr / 'export_ts_facts.sc',
         '--param', f'cpgFile={work / "js.cpg.zip"}', '--param', f'outDir={raw}'], log)
    run([sys.executable, fr / 'normalize_ts_facts.py', raw, work / 'js.json'], log)
    run([sys.executable, fr / 'state_facts.py', raw, work / 'js_state.json'], log)
    subprocess.run([sys.executable, '-c',
        f'import sys,json; sys.path.insert(0,"{fr}"); from identity_facts import derive_identities; '
        f'json.dump(derive_identities("{raw}"), open("{work}/js_identity.json","w"))'], check=True)
    with open(work / 'js_capture.json', 'w') as f:
        subprocess.run([sys.executable, fr / 'capture_facts.py', raw], stdout=f, check=True)
    return work / 'js.json'

def build_gate_build(log):
    build = ROOT / 'tests/gates/jsts-r05/build'
    if not (build / 'EndToEndRunner.class').exists():
        build.mkdir(parents=True, exist_ok=True)
        srcs = subprocess.run(['bash', '-c',
            f'find {ROOT}/core -name "*.java" -path "*src/main*"'], capture_output=True, text=True).stdout.split()
        run(['javac', '-d', build] + srcs + [ROOT / 'tests/gates/jsts-r05/EndToEndRunner.java'], log)
    return build

def engine(build, program, extras, out_path):
    r = subprocess.run(['java', '-cp', build, 'EndToEndRunner', str(program)] + [str(e) for e in extras],
                       capture_output=True, text=True)
    pathlib.Path(out_path).write_text(r.stdout + r.stderr)
    if r.returncode != 0:
        raise SystemExit(f'ENGINE FAILED ({r.returncode}) for {program} — see {out_path}')
    return r.stdout

# These are engine-consumed fact families emitted beside the normalized program.
# Keep the lists explicit: automatically loading every JSON file would allow an
# unrelated or future schema to contaminate a scan.  Language-specific producers
# may add separately-named facts (state/identity/capture for JS) below.
PROGRAM_SIDECARS = {
    'c_cpp': ('.memory.json', '.expression.json', '.reachingdef.json', '.source.json'),
    'js_ts': ('.expression.json', '.source.json'),
}

def program_sidecars(label, doc_path):
    """Return existing, engine-supported program sidecars in stable order."""
    if label not in PROGRAM_SIDECARS:
        raise ValueError(f'unknown scan side: {label}')
    return [pathlib.Path(str(doc_path) + suffix)
            for suffix in PROGRAM_SIDECARS[label]
            if pathlib.Path(str(doc_path) + suffix).exists()]

def report_side(label, doc_path, extras, build, work):
    doc = json.load(open(doc_path))
    out = engine(build, doc_path, extras, work / f'{label}.engine.out')
    sums = bind_summaries_to_functions(out, doc['functions'])
    calls_by_id = {c['id']: c for c in doc['calls']}
    rd_path = pathlib.Path(str(doc_path) + '.reachingdef.json')
    reaching = None
    if rd_path.exists():
        reaching = {f['use_id']: f for f in json.load(open(rd_path)).get('reaching_defs', [])}
    locals_defs = {}
    for a in doc.get('assignments', []):
        locals_defs[a['target_local_id']] = locals_defs.get(a['target_local_id'], 0) + 1
    rows = []; taxonomy = {}
    bodied = set()
    for c in doc['calls']: bodied.add(c['enclosing_function_id'])
    for l in doc.get('locals', []): bodied.add(l['method_id'])
    for r in doc.get('returns', []): bodied.add(r['function_id'])
    for f in doc['functions']:
        # JSTS-R07: `<lambda>N` are REAL user functions — in modern ESM/TS packages
        # they are most of the program. Dropping them made p-limit report 0
        # analyzed functions out of 190 exported methods, i.e. "not measured"
        # masquerading as "no findings". Only true non-user-code is excluded now.
        if f.get('is_external') or f['name'] in ('<global>', ':program', '<clinit>') \
                or f['name'].startswith('<operator>') or '<duplicate>' in (f.get('full_name') or ''):
            continue
        # MEASURED (stb): staging many translation units into one c2cpg run makes
        # shared headers produce '<duplicate>N' method nodes with NO body, whose
        # real definitions exist separately. Counting them inflated the corpus and
        # produced 20 phantom "abstentions". They are an artifact of the SCANNER's
        # flat staging, not findings.
        if '<duplicate>' in f.get('full_name', '') and f['id'] not in bodied:
            continue
        s = sums.get(f['id'])
        if not s: continue
        proven = bool(s['proven'] or s['may'])
        abst = (s['resolution'] == 'UNRESOLVED' or s['unknown']) and not proven
        row = {'function': f['name'], 'function_id': f['id'], 'full_name': f.get('full_name'),
               'file': f.get('file'), 'line': f.get('line'), **s}
        if abst:
            reason = classify_abstention(f, doc, calls_by_id, locals_defs, reaching)
            if reason == 'NO_RETURN_FACT':
                # A function with no value-returning path (void, constructor,
                # destructor) has NOTHING to trace. "No value to trace" is the
                # CORRECT semantic result, not a failure to resolve — so it leaves
                # the abstention taxonomy entirely.
                row['no_value_result'] = True
                rows.append(row)
                continue
            row['abstention'] = reason
            for part in reason.split('+'):
                taxonomy[part] = taxonomy.get(part, 0) + 1
        rows.append(row)
    counters = {k: doc.get(k) for k in ('cpp_memory',) if k in doc}
    return {'label': label, 'functions_analyzed': len(rows),
            'proven_flows': sum(1 for r in rows if r['proven'] or r['may']),
            'abstained': sum(1 for r in rows if 'abstention' in r),
            'abstention_taxonomy': dict(sorted(taxonomy.items(), key=lambda kv: -kv[1])),
            'rows': rows, **counters}


def _scanned_content_map(repo, work):
    """Full SHA-256 of the ACTUAL scanned source bytes (working tree: covers uncommitted/untracked).
    Keyed by basename and relpath to match the facts' file field. Trusted-runtime derived."""
    import hashlib, json as _json
    sel = _json.load(open(work / 'c.selection.json'))
    rels = []
    for g in sel.get('groups', {}).values():
        rels += list(g.get('selected_paths', []))
    m = {}
    for rel in rels:
        fp = pathlib.Path(repo) / rel
        if fp.is_file():
            h = hashlib.sha256(fp.read_bytes()).hexdigest()
            m[rel] = h; m[pathlib.Path(rel).name] = h
    return m

def oob_review(cdoc, work, log, repo, advisory_path=None, trusted_path=None):
    """Canonical entry-point stage. FAIL-LOUD: a missing/failing OOB adjudicator raises (nonzero
    scan) rather than a silent zero. Content + analyzer identity are DERIVED by trusted runtime
    (from actual scanned bytes and analyzer files on disk), never from caller labels."""
    import importlib.util
    adj_py = ROOT.parent / 'tchecker-property-adjudicator' / 'adjudicator' / 'adjudicate_oob.py'
    if not adj_py.exists():
        raise SystemExit(f'OOB stage required but adjudicator missing: {adj_py}')
    spec = importlib.util.spec_from_file_location('adjudicate_oob', adj_py)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    advisory, trusted = m.load_channels(advisory_path, trusted_path)
    scanned_content = _scanned_content_map(repo, work)
    out_dir = pathlib.Path(work) / 'oob_review'
    return m.adjudicate(cdoc, out_dir, advisory_hints=advisory, trusted_attestations=trusted,
                        scanned_content=scanned_content)   # may raise -> fail loud

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target')
    ap.add_argument('--lang', default='auto', choices=['auto', 'c', 'js'])
    ap.add_argument('--out', default=None)
    ap.add_argument('--work', default=None)
    ap.add_argument('--compile-commands', default=None,
                    help='path to compile_commands.json — drive c2cpg from the REAL build context')
    ap.add_argument('--preprocess', action='store_true',
                    help='run the C preprocessor before c2cpg (resolves macros by definition)')
    ap.add_argument('--max-c-impl', type=int, default=40,
                    help='maximum eligible C/C++ implementation files (default: 40)')
    ap.add_argument('--max-c-headers', type=int, default=20,
                    help='maximum eligible C/C++ headers (default: 20)')
    ap.add_argument('--max-js', type=int, default=40,
                    help='maximum eligible JS/TS files (default: 40)')
    ap.add_argument('--oob-hints', default=None,
                    help='UNTRUSTED advisory hints channel (e.g. LLM answers); never suppresses a candidate')
    ap.add_argument('--oob-trusted-attestations', default=None,
                    help='TRUSTED curated-attestation channel (operator-controlled); only this may suppress')
    ap.add_argument('--all-files', action='store_true',
                    help='disable all source-file caps; selection counts remain in the report')
    a = ap.parse_args()
    if not (JH / 'c2cpg.sh').exists():
        raise SystemExit('set JOERN_HOME to a joern-cli with c2cpg.sh')
    work = pathlib.Path(a.work) if a.work else pathlib.Path(tempfile.mkdtemp(prefix='scan.'))
    work.mkdir(parents=True, exist_ok=True)
    log = work / 'scan.log'
    if re.match(r'https?://|git@', a.target):
        repo = work / 'repo'
        run(['git', 'clone', '--depth', '1', a.target, repo], log)
    else:
        repo = pathlib.Path(a.target).resolve()
    build = build_gate_build(log)
    try:
        _rr = subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,text=True)
        repo_rev = _rr.stdout.strip() if _rr.returncode==0 and _rr.stdout.strip() else 'UNVERSIONED'
    except Exception:
        repo_rev = 'UNVERSIONED'
    # R03: clear a prior report at the target so a FAILED rescan cannot leave a stale-current report
    _outp0 = pathlib.Path(a.out) if a.out else work / 'report.json'
    if _outp0.exists(): _outp0.unlink()
    report = {'target': a.target, 'repo_rev_informational': repo_rev, 'sides': []}
    if a.lang in ('auto', 'c'):
        c_impl_cap = None if a.all_files else a.max_c_impl
        c_header_cap = None if a.all_files else a.max_c_headers
        cdoc = scan_c(repo, work, log, preprocess=a.preprocess, ccj=a.compile_commands,
                      impl_cap=c_impl_cap, header_cap=c_header_cap)
        if cdoc:
            extras = program_sidecars('c_cpp', cdoc)
            side = report_side('c_cpp', cdoc, extras, build, work)
            side['source_selection'] = json.load(open(work / 'c.selection.json'))
            report['sides'].append(side)
            _oobr = oob_review(cdoc, work, log, repo, advisory_path=a.oob_hints,
                               trusted_path=a.oob_trusted_attestations)
            if _oobr is not None:
                side['oob_review'] = _oobr
    if a.lang in ('auto', 'js'):
        js_cap = None if a.all_files else a.max_js
        jdoc = scan_js(repo, work, log, cap=js_cap)
        if jdoc:
            extras = program_sidecars('js_ts', jdoc)
            extras += [work / 'js_state.json', work / 'js_identity.json', work / 'js_capture.json']
            side = report_side('js_ts', jdoc, [e for e in extras if e.exists()], build, work)
            side['source_selection'] = json.load(open(work / 'js.selection.json'))
            report['sides'].append(side)
    outp = pathlib.Path(a.out) if a.out else work / 'report.json'
    json.dump(report, open(outp, 'w'), indent=1, sort_keys=True)
    for side in report['sides']:
        print(f"[{side['label']}] analyzed={side['functions_analyzed']} "
              f"proven={side['proven_flows']} abstained={side['abstained']}")
        for k, v in list(side['abstention_taxonomy'].items())[:8]:
            print(f"    {v:3d}  {k}")
    print(f'REPORT={outp}')

if __name__ == '__main__':
    main()
