#!/usr/bin/env python3
"""SOURCE-R01 (CHARACTERIZE ONLY): where does attacker-controlled data actually
ENTER independently authored C programs, and which source kinds co-occur with
security-sensitive sinks? No engine changes; this decides which source classes
are worth modelling at all."""
import re, sys, pathlib
from collections import Counter, defaultdict

SOURCES = {
 'FILE_INPUT':     r'\b(fread|fgets|fscanf|getline|read|fgetc|getc)\s*\(',
 'NETWORK_INPUT':  r'\b(recv|recvfrom|accept|read_socket)\s*\(',
 'PROCESS_ARGUMENT': r'\bargv\s*\[',
 'ENVIRONMENT':    r'\b(getenv|secure_getenv)\s*\(',
 'STDIN':          r'\b(gets|scanf|getchar)\s*\(',
 'PARAMETER':      None,   # counted structurally below
}
SINKS = r'\b(memcpy|memmove|strcpy|strcat|sprintf|snprintf|malloc|calloc|realloc|alloca|system|execl|printf)\s*\('

def scan(root, label):
    src_tot = Counter(); fn_with_sink = 0; sink_fn_sources = Counter(); fns = 0
    for p in pathlib.Path(root).rglob('*.c'):
        try: text = p.read_text(errors='replace')
        except Exception: continue
        # crude function split: lines from a '{' at col 0 back to the signature
        blocks = re.split(r'\n(?=[A-Za-z_][\w \*]*\([^;]*\)\s*\{)', text)
        for b in blocks:
            if '{' not in b: continue
            fns += 1
            has_sink = re.search(SINKS, b) is not None
            present = set()
            for k, rx in SOURCES.items():
                if rx and re.search(rx, b):
                    src_tot[k] += 1; present.add(k)
            # PARAMETER source = the block's signature has a pointer/array param
            sig = b.split('{')[0]
            if re.search(r'\((?![\s]*void[\s]*\))[^)]*[\w]+\s*[\*\[]', sig):
                src_tot['PARAMETER'] += 1; present.add('PARAMETER')
            if has_sink:
                fn_with_sink += 1
                for k in present: sink_fn_sources[k] += 1
                if not present: sink_fn_sources['NO_SOURCE_IN_FUNCTION'] += 1
    return label, fns, src_tot, fn_with_sink, sink_fn_sources

rows = [scan(r, l) for r, l in [(sys.argv[i], sys.argv[i+1]) for i in range(1, len(sys.argv), 2)]]
agg_src = Counter(); agg_sink = Counter(); TF = TS = 0
for label, fns, st, fws, sfs in rows:
    TF += fns; TS += fws; agg_src += st; agg_sink += sfs
    print(f"{label}: {fns} functions, {fws} containing a sensitive sink")
print(f"\nSOURCE KINDS PRESENT ({TF} functions total):")
for k, v in agg_src.most_common(): print(f"  {v:4d}  {k}")
print(f"\nWHAT SOURCES CO-OCCUR WITH A SINK ({TS} sink-bearing functions):")
for k, v in agg_sink.most_common():
    print(f"  {v:4d}  {100*v//TS if TS else 0:3d}%  {k}")
