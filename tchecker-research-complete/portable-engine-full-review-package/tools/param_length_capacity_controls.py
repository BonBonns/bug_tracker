#!/usr/bin/env python3
"""PARAM-CAP-R01 (task #44) required control matrix.

Covers every control named by direct instruction:
  1. Tremor vulnerable case (real, freshly rebuilt via c2cpg from the committed fixture)
  2. Tremor patched case (real, same)
  3. a correctly bounded pointer/length loop (clean synthetic, distinct from Tremor)
  4. an unrelated adjacent integer parameter (must NOT be used as capacity)
  5. byte length versus element count (sizeof-scaled index -> abstain, not silently wrong)
  6. pointer arithmetic reducing remaining capacity (literal offset)
  7. multiple possible length parameters (ambiguity abstention)
  8. overflow in `n * sizeof(*a)` (call-site allocation-evidence overflow-risk gate)
  plus: OOB_WRITE (memcpy-surface) must never duplicate a PARAM-CAP-R01 candidate for the same
  real sink -- verified directly on the real Tremor bundle.

Real controls (1, 2, and the dedup check) rebuild fresh evidence via the real c2cpg pipeline
(same chain run_pipeline_one.py and the pilot's own run_single_file_bundle.py use) so this file
is reproducible from a clean checkout, independent of any /tmp state from an earlier session.
"""
import json, os, pathlib, re, subprocess, sys, tempfile, time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import param_length_capacity as plc
import oob_index_write_verdict as oiw
import oob_write_verdict as owv

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"
TREMOR_DIR = "/home/user/bug_tracker/tchecker-research-complete/docs/moz-oob-r01/primary-artifacts"

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def build_bundle(src_file, work_dir):
    """Real c2cpg -> export -> normalize chain, same as run_pipeline_one.py / the pilot's
    run_single_file_bundle.py -- inlined here since this test must stand on its own on this
    branch (that pilot script lives on a different, docs-only branch)."""
    os.makedirs(work_dir, exist_ok=True)
    cpp_bin = os.path.join(work_dir, "cpp.cpg.bin")
    r = subprocess.run([f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin, src_file],
                        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"c2cpg failed: {r.stderr[-2000:]}")
    cpp_raw = os.path.join(work_dir, "cpp_raw")
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script",
                         f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
                         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
                        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"export failed: {r.stdout[-2000:]}")
    cpp_facts = os.path.join(work_dir, "cpp_facts.json")
    r = subprocess.run([sys.executable, f"{CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"normalize failed: {r.stderr[-2000:]}")
    return cpp_facts


# ============================== controls 1, 2, and dedup ==============================
with tempfile.TemporaryDirectory() as td:
    vuln_facts = build_bundle(f"{TREMOR_DIR}/tremor_codebook_VULN.c", os.path.join(td, "vuln"))
    patched_facts = build_bundle(f"{TREMOR_DIR}/tremor_codebook_PATCHED.c", os.path.join(td, "patched"))

    v_idx = oiw.emit_candidates(vuln_facts)
    p_idx = oiw.emit_candidates(patched_facts)
    v_write = owv.emit_candidates(vuln_facts)
    p_write = owv.emit_candidates(patched_facts)

    ck("1. Tremor VULN: real param-length-pair candidate found (a[o+j], length_param=n)",
       any(c.get('array') == 'a' and c.get('index_expr') == 'o+j' and
           c.get('length_param_name') == 'n' for c in v_idx))
    ck("2. Tremor PATCHED: the same site is suppressed (real, correctly-matched o+j<n guard)",
       not any(c.get('array') == 'a' and c.get('index_expr') == 'o+j' for c in p_idx))
    # Phase 2 (real CFG dominance + loop-iteration reasoning, task #44 second review round):
    # the SECOND real vulnerable sink, vorbis_book_decodev_add (a[i++]), is now also correctly
    # discriminated -- plain textual guard existence could not (the outer for(i=0;i<n;) is
    # unchanged between vuln and patched); real dominance + loop-header-containment can, because
    # the real fix moves the check to the INNER loop's own header (re-evaluated every iteration)
    # instead of only the outer loop's (checked once per outer pass).
    ck("1b. Tremor VULN: SECOND real sink also found (a[i++] in vorbis_book_decodev_add, length_param=n)",
       any(c.get('array') == 'a' and c.get('index_expr') == 'i++' and
           c.get('length_param_name') == 'n' for c in v_idx))
    ck("2b. Tremor PATCHED: the second sink is ALSO suppressed (real CFG dominance + "
       "loop-iteration-safety proof on the inner loop's own new guard -- not textual matching, "
       "which cannot distinguish this revision from the vulnerable one at all)",
       not any(c.get('array') == 'a' and c.get('index_expr') == 'i++' for c in p_idx))
    # decodevv_add: treated explicitly, per direct instruction -- its real vulnerability is on a
    # NESTED/2D index (a[chptr++][i], the second dimension), entirely outside this producer's
    # single-level indexAccess model. Verified: NO ad hoc flattening was added, so it correctly
    # produces no candidate for its own real vulnerable line at all (an honest, disclosed
    # UNSUPPORTED verdict via silent abstention, not a false claim of either safety or detection).
    decodevv_fid = [f['id'] for f in json.load(open(vuln_facts))['functions']
                    if f['name'] == 'vorbis_book_decodevv_add'][0]
    ck("decodevv_add: real 2D vulnerability (a[chptr++][i]) correctly produces NO candidate -- "
       "no ad hoc flattening rule was added; this is an explicit, disclosed unsupported case, "
       "not a false negative introduced by this phase",
       not any(c.get('function_id') == decodevv_fid for c in v_idx))

    ck("dedup: OOB_WRITE (memcpy-surface) never ALSO fires on this real site (VULN)",
       len(v_write) == 0)
    ck("dedup: OOB_WRITE (memcpy-surface) never ALSO fires on this real site (PATCHED)",
       len(p_write) == 0)


# ============================== synthetic controls (3-8) ==============================
def make_facts(func_name, params, calls, assignments=None, locals_=None):
    return {
        'functions': [{'id': 1, 'name': func_name, 'full_name': func_name, 'parameters': params}],
        'calls': calls,
        'assignments': assignments or [],
        'locals': locals_ or [],
    }


def param(idx, id_, name, type_full_name):
    return {'index': idx, 'id': id_, 'name': name, 'type_full_name': type_full_name}


def cmp_call(id_, code, lhs_code, rhs_code, rhs_kind, rhs_id, fn=1, op='<operator>.lessThan'):
    return {'id': id_, 'name': op, 'code': code, 'enclosing_function_id': fn,
            'arguments': [{'index': 0, 'value_ref': {'code': lhs_code}},
                          {'index': 1, 'value_ref': {'code': rhs_code, 'kind': rhs_kind, 'id': rhs_id}}]}


def idx_call(id_, code, fn=1, line=1):
    return {'id': id_, 'name': '<operator>.indexAccess', 'code': code,
            'enclosing_function_id': fn, 'file': 'x.c', 'line': line}


def assign(id_, target_local_id, rhs_code, fn=1):
    return {'id': id_, 'function_id': fn, 'target_local_id': target_local_id,
            'value_ref': {'code': rhs_code}}


# --- 3. correctly bounded pointer/length loop ---
facts3 = make_facts('f3', [param(0, 10, 'buf', 'char*'), param(1, 11, 'n', 'int')],
                     calls=[idx_call(100, 'buf[i]', line=1),
                            cmp_call(200, 'i<n', 'i', 'n', 'PARAMETER', 11)])
d3 = plc.derive_length_param(facts3, 1, 'i')
ck("3. correctly bounded pointer/length loop: length param resolved for a real guard candidate",
   d3['status'] == 'RESOLVED' and d3['length_param']['name'] == 'n')

# --- 4. unrelated adjacent integer parameter ---
facts4 = make_facts('f4', [param(0, 10, 'buf', 'char*'), param(1, 11, 'unrelated', 'int')],
                     calls=[idx_call(100, 'buf[k]', line=1)])
d4 = plc.derive_length_param(facts4, 1, 'k')
ck("4. unrelated adjacent integer parameter: NOT used as capacity (abstain, no evidence)",
   d4['status'] == 'ABSTAIN_NONE')

# --- 5. byte length versus element count ---
d5 = plc.derive_length_param(facts3, 1, 'i*sizeof(buf[0])')
ck("5. byte-vs-element scaling in the index expression: abstain rather than silently mismatch units",
   d5['status'] == 'ABSTAIN_BYTE_ELEMENT_SCALING')

# --- 6. pointer arithmetic reducing remaining capacity ---
facts6 = make_facts('f6', [param(0, 10, 'buf', 'char*'), param(1, 11, 'n', 'int')],
                     calls=[], locals_=[{'method_id': 1, 'id': 900, 'name': 'p2'}],
                     assignments=[assign(300, 900, 'buf + 5')])
base, offset, status = plc.resolve_pointer_base(facts6, 1, 'p2')
ck("6. pointer arithmetic (literal offset) resolved: base=buf, offset=5",
   status == 'OFFSET_RESOLVED' and base['name'] == 'buf' and offset == 5)
facts6b = make_facts('f6b', [param(0, 10, 'buf', 'char*'), param(1, 11, 'n', 'int'), param(2, 12, 'k', 'int')],
                      calls=[], locals_=[{'method_id': 1, 'id': 901, 'name': 'p3'}],
                      assignments=[assign(301, 901, 'buf + k')])
base2, offset2, status2 = plc.resolve_pointer_base(facts6b, 1, 'p3')
ck("6b. pointer arithmetic (non-literal offset) correctly UNRESOLVED, not guessed",
   status2 == 'OFFSET_UNRESOLVED' and offset2 is None)

# --- 7. multiple possible length parameters ---
facts7 = make_facts('f7', [param(0, 10, 'buf', 'char*'), param(1, 11, 'n1', 'int'), param(2, 12, 'n2', 'int')],
                     calls=[idx_call(100, 'buf[m]', line=1)],
                     locals_=[{'method_id': 1, 'id': 902, 'name': 'm'}],
                     assignments=[assign(302, 902, 'n1+n2')])
d7 = plc.derive_length_param(facts7, 1, 'm')
ck("7. multiple possible length parameters (both n1 and n2 reach the index): ambiguous abstention",
   d7['status'] == 'ABSTAIN_AMBIGUOUS' and
   {p['name'] for p in d7['ambiguous_candidates']} == {'n1', 'n2'})

# --- 8. overflow in n * sizeof(*a) ---
ck("8a. narrow int length param * sizeof(...) -> flagged as overflow risk",
   plc.has_overflow_risk_multiplication('n * sizeof(*a)', 'int'))
ck("8b. size_t (wide) length param * sizeof(...) -> NOT flagged (provably safe width)",
   not plc.has_overflow_risk_multiplication('n * sizeof(*a)', 'size_t'))
ck("8c. no multiplication at all -> not flagged",
   not plc.has_overflow_risk_multiplication('n', 'int'))

print(f"PARAM_LENGTH_CAPACITY_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
