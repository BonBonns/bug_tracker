#!/usr/bin/env python3
"""Proc A / baseline dump: per-site non-bare recognized-memcpy V1 records from a
given tools tree. Args: <tools_dir> <cache_dir> <out.json>. No cross-tree import
risk -- run in its own process with exactly one tools tree on sys.path."""
import glob, json, os, re, sys, importlib.util
tools_dir, cache_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, tools_dir)


def L(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(tools_dir, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


P = L("oob_runtime_capacity_verdict")
from callee_contracts import CALLEE_CONTRACTS
BARE = re.compile(r'[A-Za-z_]\w*')


def nonbare_sites(d):
    out = []
    for c in d.get('calls', []):
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        dest = (args[da].get('code') or '').strip()
        if dest and not re.fullmatch(BARE, dest):
            out.append((c.get('enclosing_function_id'), dest, c.get('line')))
    return out


rows = {}
for cpp in sorted(glob.glob(os.path.join(cache_dir, "*.cpp.json"))):
    sid = os.path.basename(cpp).split('.')[0]
    d = json.load(open(cpp))
    sites = nonbare_sites(d)
    if not sites:
        continue
    recs = P.analyze_operations(cpp)
    rec_by_key = {(r.get('dest'), r.get('line')): r for r in recs}
    for (fn, dest, line) in sites:
        r = rec_by_key.get((dest, line))
        key = f"{sid}|{r.get('function') if r else fn}|{dest}|{line}"
        rows[key] = {
            "sid": sid, "function": r.get('function') if r else None,
            "dest": dest, "line": line,
            "analysis_status": r.get('analysis_status') if r else "<DROPPED>",
            "reason_code": r.get('reason_code') if r else None,
            "destination_form": r.get('destination_form') if r else None,
        }
json.dump(rows, open(out_path, "w"), indent=0, sort_keys=True)
print(f"{tools_dir}: {len(rows)} non-bare site records -> {out_path}")
