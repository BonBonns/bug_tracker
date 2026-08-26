#!/usr/bin/env python3
import csv, json, sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit('usage: generate_bridge.py nodes.csv resolution_manifest.json frontend_resolution.tsv')
node_path, manifest_path, out_path = map(Path, sys.argv[1:])
with node_path.open(newline='') as f:
    rows=list(csv.DictReader(f, delimiter='\t'))

calls={}
methods={}
for r in rows:
    typ=r.get('type','')
    if typ in ('AST_METHOD_CALL','AST_STATIC_CALL'):
        try: line=int(r.get('lineno:int') or 0)
        except ValueError: line=0
        calls.setdefault(line,[]).append(int(r['id:int']))
    if typ=='AST_METHOD':
        key=f"{r.get('classname','')}.{r.get('name','')}"
        methods.setdefault(key,[]).append(int(r['id:int']))

manifest=json.loads(manifest_path.read_text())
records=[]
for item in manifest:
    line=int(item['line']); resolution=item['resolution'].upper()
    candidates=calls.get(line,[])
    if len(candidates)!=1:
        raise SystemExit(f'line {line}: expected exactly one call node, got {candidates}')
    target_ids=[]
    for target in item.get('targets',[]):
        ids=methods.get(target,[])
        if len(ids)!=1:
            raise SystemExit(f'target {target}: expected exactly one method node, got {ids}')
        target_ids.extend(ids)
    records.append((candidates[0], resolution, ','.join(map(str,target_ids))))

with out_path.open('w') as f:
    for call_id,resolution,targets in records:
        f.write(f'{call_id}\t{resolution}\t{targets}\n')
print(f'wrote {len(records)} records to {out_path}')
