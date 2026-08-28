#!/usr/bin/env python3
"""Build the staged Magma feasibility manifest (NO model calls, no cherry-picking).
One row per bug patch, advancing through explicit stages so gains/losses are visible:

  catalogued -> property_candidate -> source_available -> write_mapped ->
  pair_available -> scanner_recognized -> packet_valid -> eligible

Early stages are determined mechanically from the patches. The last three are gated on the
build-driven scanning integration (see MAGMA_FEASIBILITY.md) and are recorded as
'pending_build_integration', with a definite 'no' where already known (no destination
write, or not a capacity-write property).

Usage: magma_manifest.py <magma_repo_dir>
"""
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

# property: a write extent / index exceeding a destination capacity (frozen classifier)
LEN = re.compile(r'(len\b|length|decodedSize|\bnum\b|count|loop_count|\bpos\b|indx|offset'
                 r'|avail|precision|getNumPixelComps|_left|eticklen|msg_len)', re.I)
CAP = re.compile(r'(sizeof|ARRAY_LEN|capacity|_size\b|->size|\.size|buf_size|tbuf_size'
                 r'|header\.len|->len\b|max_|_LENGTH|MAX_CHANNELS)', re.I)
INTOV = re.compile(r'(INT_MAX|SIZE_MAX|LLONG_MAX|MAX_SIZE_T|<<|0x7fffffff)')
EXCL = re.compile(r'isfinite|INT_MIN|==\s*NULL|!=\s*NULL|instate|->type\s*==|nullptr')

COPY = re.compile(r'\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf'
                  r'|vsprintf|memset|wmemcpy|wcscpy)\b')
WRAP = re.compile(r'\b(\w*_?(?:memcpy|memmove|strcpy|strncpy|strcat))\s*\(')
IDXW = re.compile(r'\[[^\]\n]+\]\s*=(?!=)')
DEREFW = re.compile(r'\*\s*\w+\s*=(?!=)')


def canary(txt):
    m = re.search(r'MAGMA_LOG\("%MAGMA_BUG%", (.*)\);', txt)
    return m.group(1) if m else None


def hunk_lines(txt):
    """context (' ') and added ('+') lines, excluding removed ('-'), file headers, and any
    MAGMA marker/canary line (must not be read as a write)."""
    out = []
    for l in txt.splitlines():
        if l[:1] in ("+", " ") and not l.startswith("+++") and "MAGMA" not in l:
            out.append(l[1:])
    return out


def find_write(lines):
    for l in lines:
        if COPY.search(l):
            return "copy_sink", l.strip()[:80]
    for l in lines:
        if WRAP.search(l):
            return "wrapper_copy", l.strip()[:80]
    for l in lines:
        if IDXW.search(l):
            return "array_index_write", l.strip()[:80]
    for l in lines:
        if DEREFW.search(l):
            return "pointer_deref_write", l.strip()[:80]
    return None, None


def main():
    repo = sys.argv[1]
    targets_with_fetch = {os.path.basename(os.path.dirname(p))
                          for p in glob.glob(os.path.join(repo, "targets/*/fetch.sh"))}
    rows = []
    for p in sorted(glob.glob(os.path.join(repo, "targets/*/patches/bugs/*.patch"))):
        txt = open(p, errors="replace").read()
        bid = os.path.basename(p)[:-6]
        target = os.path.basename(p.split("/patches/")[0])
        fm = re.search(r'\+\+\+ b/(.+)', txt)
        srcfile = fm.group(1).strip() if fm else None
        cond = canary(txt)
        # stage: property_candidate
        prop = bool(cond and re.search(r'(>=|<=|>|<)', cond) and LEN.search(cond)
                    and CAP.search(cond) and not INTOV.search(cond) and not EXCL.search(cond))
        # stage: write_mapped (from the patch hunk; 'needs_source' if not visible here)
        wkind, wtext = find_write(hunk_lines(txt))
        write_mapped = "yes" if wkind else "needs_source"
        # stage: pair_available
        pair = "MAGMA_ENABLE_FIXES" in txt
        # stage: source_available
        src = target in targets_with_fetch
        # later stages gated on build integration
        if not prop:
            later = "no_not_capacity_write_property"
        elif wkind is None:
            later = "pending_write_unmapped_needs_source"
        elif wkind in ("wrapper_copy",):
            later = "pending_build+sink_alias"        # e.g. _TIFFmemcpy
        else:
            later = "pending_build_integration"
        rows.append({
            "bug": bid, "target": target, "file": srcfile,
            "has_canary": bool(cond), "canary": cond,
            "catalogued": True,
            "property_candidate": prop,
            "source_available": src,
            "write_mapped": write_mapped, "write_kind": wkind, "write_op": wtext,
            "pair_available": pair,
            "scanner_recognized": later if later.startswith("pending") or later.startswith("no") else "pending_build_integration",
            "packet_valid": "pending_build_integration" if prop else "no",
            "eligible": "pending_build_integration" if (prop and pair and src) else "no",
        })

    # funnel (stages that are mechanically decided now)
    funnel = {
        "catalogued": len(rows),
        "has_canary": sum(r["has_canary"] for r in rows),
        "property_candidate": sum(r["property_candidate"] for r in rows),
        "source_available (of property_candidates)":
            sum(1 for r in rows if r["property_candidate"] and r["source_available"]),
        "write_mapped_in_patch (of property_candidates)":
            sum(1 for r in rows if r["property_candidate"] and r["write_mapped"] == "yes"),
        "write_needs_source (of property_candidates)":
            sum(1 for r in rows if r["property_candidate"] and r["write_mapped"] == "needs_source"),
        "pair_available (of property_candidates)":
            sum(1 for r in rows if r["property_candidate"] and r["pair_available"]),
        "pending_build_integration_beyond_here": "scanner_recognized / packet_valid / eligible",
    }
    write_kind_dist = Counter(str(r["write_kind"]) for r in rows if r["property_candidate"])

    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "magma")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "feasibility_manifest.json"), "w") as fh:
        json.dump({"model_calls": 0, "funnel": funnel,
                   "write_kind_distribution_of_candidates": dict(write_kind_dist),
                   "rows": rows}, fh, indent=2, sort_keys=True, default=str)
    cols = ["bug", "target", "file", "property_candidate", "source_available",
            "write_mapped", "write_kind", "pair_available", "scanner_recognized",
            "packet_valid", "eligible", "canary"]
    with open(os.path.join(outdir, "feasibility_manifest.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print("MAGMA STAGED FEASIBILITY FUNNEL (mechanical stages; later stages pending build):")
    for k, v in funnel.items():
        print(f"  {k:52} {v}")
    print(f"\nwrite-kind of property candidates: {dict(write_kind_dist)}")
    print("\nproperty candidates (bug : write_kind : canary):")
    for r in rows:
        if r["property_candidate"]:
            print(f"  {r['bug']:7} {str(r['write_kind']):20} {(r['canary'] or '')[:52]}")
    print(f"\nmanifest -> {outdir}/feasibility_manifest.{{json,csv}}  ({len(rows)} rows)")


if __name__ == "__main__":
    main()
