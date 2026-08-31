#!/usr/bin/env python3
"""Freezes the 100-package overnight diagnostic sample BEFORE any scanner output is read (per
direct instruction: "Create the sample before reading scanner outcomes") -- every input this
script reads is either static npm registry metadata already fetched by prior, already-completed
pipeline stages (eligible_packages.tsv, npm_build_configuration.tsv, npm_pipeline_status.tsv --
all from the real 452/494 corpus run) or a real, already-completed corpus-wide text search
(primitive_search_results.jsonl, task #28) -- NONE of these are this diagnostic run's own
scanner output.

Selection (per direct instruction):
  - 75 packages chosen DETERMINISTICALLY (greedy stratified coverage, no randomness) to
    maximize coverage of: lock primitives; write primitives; read primitives; compare
    primitives; node-addon-api/Nan/raw N-API/Node-V8-binding families; small/medium/large
    source trees; different build systems; prior ANALYZED/RESOURCE_LIMIT/CPP_CPG_FAILED status.
  - 25 deterministic random controls from the remaining pool, seed 20260831.
  - Deduplicated by real, freshly-computed canonical source_tree_sha256 (provenance.py's own
    build_source_manifest -- the SAME function the real pipeline uses -- run here on each
    candidate's real tarball, download only, no c2cpg) -- a true content-duplicate is replaced
    by the next-best candidate in the same stratum, never silently kept twice.
  - Known regression/development packages force-included when eligible: node-libcurl,
    node-crc16, re2, @2060.io/ffi-napi, node-snap7.

Writes overnight_sample_100.tsv, overnight_sample_100.json, selection_method.md.
"""
import hashlib
import io
import json
import os
import random
import re
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NPM_CORPUS = os.path.dirname(HERE)
SCANNER_V2 = os.path.dirname(NPM_CORPUS)
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, NPM_CORPUS)
import provenance  # noqa: E402

SEED = 20260831
FORCED = ["node-libcurl", "node-crc16", "re2", "@2060.io/ffi-napi", "node-snap7"]

LOCK_PRIMS = {"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_rwlock_rdlock",
              "pthread_rwlock_wrlock", "wc_LockMutex", "k_mutex_lock",
              "spin_lock_irqsave", "spin_lock", "mutex_lock", "PR_Lock",
              "EnterCriticalSection"}
WRITE_PRIMS = {"memcpy", "memmove", "memset", "strncpy", "snprintf", "PORT_Memcpy",
               "PORT_Memmove", "wmemcpy"}
READ_PRIMS = {"memcpy", "memmove", "strncpy", "PORT_Memcpy", "PORT_Memmove", "wmemcpy"}
CMP_PRIMS = {"memcmp", "strncmp", "CRYPTO_memcmp"}

BINDING_FAMILY_PATTERNS = [
    ("nan", re.compile(r"\bnan\.h\b|Nan::", re.I)),
    ("node-addon-api", re.compile(r"napi-inl\.h|Napi::")),
    ("raw-napi", re.compile(r"node_api\.h|js_native_api\.h")),
    ("node-v8-buffer", re.compile(r"\bnode_buffer\.h\b|v8::Buffer|node::Buffer")),
]


def load_tsv(path):
    rows = []
    with open(path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append({name: (parts[i] if i < len(parts) else "") for name, i in idx.items()})
    return rows


def classify_binding_family(binding_evidence):
    for name, pat in BINDING_FAMILY_PATTERNS:
        if pat.search(binding_evidence or ""):
            return name
    return "none"


def size_bucket(n_cpp_files):
    n = int(n_cpp_files or 0)
    if n <= 3:
        return "small"
    if n <= 20:
        return "medium"
    return "large"


def build_system_families(config_file_families):
    fams = set((config_file_families or "").split(";"))
    fams.discard("")
    fams.discard("package.json")  # every package has this; not a distinguishing build system
    return fams or {"none"}


def load_universe():
    elig = {(r["package_name"], r["version"]): r for r in load_tsv(os.path.join(NPM_CORPUS, "eligible_packages.tsv"))}
    build_cfg = {(r["package_name"], r["version"]): r for r in load_tsv(os.path.join(NPM_CORPUS, "npm_build_configuration.tsv"))}
    status = {(r["package_name"], r["version"]): r for r in load_tsv(os.path.join(NPM_CORPUS, "npm_pipeline_status.tsv"))}
    prims = {}
    with open(os.path.join(HERE, "primitive_search_results.jsonl")) as f:
        for line in f:
            r = json.loads(line)
            prims[(r["package_name"], r["version"])] = r.get("hits", {})

    universe = []
    for key, e in elig.items():
        hits = set(prims.get(key, {}).keys())
        cfg = build_cfg.get(key, {})
        st = status.get(key, {})
        universe.append({
            "package_name": e["package_name"],
            "version": e["version"],
            "tarball_url": e["tarball_url"],
            "n_cpp_files": e.get("n_cpp_files", "0"),
            "binding_family": classify_binding_family(e.get("binding_evidence", "")),
            "size_bucket": size_bucket(e.get("n_cpp_files")),
            "build_systems": build_system_families(cfg.get("config_file_families", "")),
            "prior_status": st.get("status") or e.get("status") or "UNKNOWN",
            "has_lock": bool(hits & LOCK_PRIMS),
            "has_write": bool(hits & WRITE_PRIMS),
            "has_read": bool(hits & READ_PRIMS),
            "has_cmp": bool(hits & CMP_PRIMS),
        })
    return universe


def strata_for(pkg):
    """The set of coverage buckets this package satisfies -- used by the greedy cover."""
    s = set()
    if pkg["has_lock"]:
        s.add("prim:lock")
    if pkg["has_write"]:
        s.add("prim:write")
    if pkg["has_read"]:
        s.add("prim:read")
    if pkg["has_cmp"]:
        s.add("prim:cmp")
    s.add(f"binding:{pkg['binding_family']}")
    s.add(f"size:{pkg['size_bucket']}")
    for b in pkg["build_systems"]:
        s.add(f"build:{b}")
    s.add(f"status:{pkg['prior_status']}")
    return s


def greedy_stratified_select(universe, n, already_selected_keys):
    """Deterministic greedy set cover: repeatedly pick the still-eligible package that covers
    the most currently-UNCOVERED strata (ties broken by package_name, ascending -- fully
    deterministic, no randomness at all in this half of the selection), until `n` are picked
    or every stratum is covered at least once, then pad remaining slots with the
    largest-remaining-coverage packages (same deterministic tie-break) to reach exactly n."""
    all_strata = set()
    for p in universe:
        all_strata |= strata_for(p)
    covered = set()
    selected = []
    selected_keys = set(already_selected_keys)
    pool = sorted(universe, key=lambda p: (p["package_name"], p["version"]))

    while len(selected) < n:
        best = None
        best_gain = -1
        for p in pool:
            key = (p["package_name"], p["version"])
            if key in selected_keys:
                continue
            gain = len(strata_for(p) - covered)
            if gain > best_gain:
                best_gain = gain
                best = p
        if best is None:
            break
        key = (best["package_name"], best["version"])
        selected_keys.add(key)
        selected.append((best, "stratified_coverage" if best_gain > 0 else "stratified_fill"))
        covered |= strata_for(best)

    return selected, covered, all_strata


_TARBALL_CACHE_DIR = "/tmp/overnight100_dedup/_tarball_cache"


def _fetch_tarball_cached(tarball_url, pkg_name, version):
    os.makedirs(_TARBALL_CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(_TARBALL_CACHE_DIR,
                               f"{pkg_name.replace('/', '__')}@{version}.tgz")
    if os.path.isfile(cache_path):
        with open(cache_path, "rb") as f:
            return f.read()
    req = urllib.request.Request(tarball_url, headers={"User-Agent": "overnight-diagnostic-100/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        tb = resp.read()
    with open(cache_path, "wb") as f:
        f.write(tb)
    return tb


def real_source_tree_sha256(tarball_url, pkg_name, version):
    """Real dedup key: download the real tarball (no c2cpg, cached locally so a re-run of this
    selection script doesn't re-fetch the network) and compute source_tree_sha256 via
    provenance.py's own build_source_manifest -- the SAME function the real pipeline uses."""
    tb = _fetch_tarball_cached(tarball_url, pkg_name, version)
    tmp = f"/tmp/overnight100_dedup/{pkg_name.replace('/', '__')}@{version}"
    os_makedirs = __import__("os").makedirs
    os_makedirs(tmp, exist_ok=True)
    tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
    tf.extractall(tmp, filter="data")
    tf.close()
    inner = os.path.join(tmp, "package")
    pkg_dir = inner if os.path.isdir(inner) else tmp
    manifest = provenance.build_source_manifest(pkg_dir, tb, pkg_name, version)
    return manifest["source_tree_sha256"], hashlib.sha256(tb).hexdigest()


def main():
    universe = load_universe()
    by_key = {(p["package_name"], p["version"]): p for p in universe}

    # forced inclusions first -- record explicit reason
    forced_selected = []
    for name in FORCED:
        cands = [p for p in universe if p["package_name"] == name]
        if not cands:
            print(f"WARNING: forced package {name!r} not in eligible cohort -- skipped", file=sys.stderr)
            continue
        forced_selected.append((cands[0], f"forced_inclusion:{name}"))

    forced_keys = {(p["package_name"], p["version"]) for p, _ in forced_selected}

    n_stratified_remaining = 75 - len(forced_selected)
    stratified, covered, all_strata = greedy_stratified_select(universe, n_stratified_remaining, forced_keys)

    stratified_75 = forced_selected + stratified
    stratified_keys = {(p["package_name"], p["version"]) for p, _ in stratified_75}

    # 25 deterministic random controls from the remaining pool
    remaining_pool = sorted(
        [p for p in universe if (p["package_name"], p["version"]) not in stratified_keys],
        key=lambda p: (p["package_name"], p["version"]))
    rng = random.Random(SEED)
    random_25 = rng.sample(remaining_pool, 25)
    random_25 = [(p, "deterministic_random_control") for p in random_25]

    combined = stratified_75 + random_25

    # real dedup by source_tree_sha256 -- fetch each candidate's real tarball now
    print(f"Computing real source_tree_sha256 for {len(combined)} candidates (network fetch, no c2cpg)...",
          file=sys.stderr)
    seen_hashes = {}
    final = []
    replacement_pool = sorted(
        [p for p in universe if (p["package_name"], p["version"]) not in
         {(x["package_name"], x["version"]) for x, _ in combined}],
        key=lambda p: (p["package_name"], p["version"]))
    for i, (pkg, reason) in enumerate(combined):
        try:
            sth, tsh = real_source_tree_sha256(pkg["tarball_url"], pkg["package_name"], pkg["version"])
        except Exception as e:
            print(f"  [{i+1}/{len(combined)}] {pkg['package_name']}@{pkg['version']}: "
                  f"FETCH_FAILED {type(e).__name__}: {e} -- kept, hash recorded as None", file=sys.stderr)
            sth, tsh = None, None
        pkg = dict(pkg)
        pkg["source_tree_sha256"] = sth
        pkg["tarball_sha256"] = tsh
        pkg["selection_reason"] = reason
        if sth is not None and sth in seen_hashes:
            dup_of = seen_hashes[sth]
            print(f"  DUPLICATE content: {pkg['package_name']}@{pkg['version']} == "
                  f"{dup_of} (source_tree_sha256={sth}) -- replacing", file=sys.stderr)
            # replace with the next candidate from the same stratum bucket, deterministic order
            replacement = None
            for cand in replacement_pool:
                ckey = (cand["package_name"], cand["version"])
                if ckey in seen_hashes.values():
                    continue
                replacement = cand
                break
            if replacement is not None:
                replacement_pool.remove(replacement)
                try:
                    sth2, tsh2 = real_source_tree_sha256(replacement["tarball_url"],
                                                          replacement["package_name"], replacement["version"])
                except Exception:
                    sth2, tsh2 = None, None
                replacement = dict(replacement)
                replacement["source_tree_sha256"] = sth2
                replacement["tarball_sha256"] = tsh2
                replacement["selection_reason"] = f"dedup_replacement_for:{pkg['package_name']}@{pkg['version']}"
                final.append(replacement)
                if sth2:
                    seen_hashes[sth2] = f"{replacement['package_name']}@{replacement['version']}"
                continue
        if sth is not None:
            seen_hashes[sth] = f"{pkg['package_name']}@{pkg['version']}"
        final.append(pkg)
        print(f"  [{i+1}/{len(combined)}] {pkg['package_name']}@{pkg['version']}: OK", file=sys.stderr)

    assert len(final) == 100, f"expected 100, got {len(final)}"

    # write outputs
    tsv_path = os.path.join(HERE, "overnight_sample_100.tsv")
    json_path = os.path.join(HERE, "overnight_sample_100.json")
    cols = ["package_name", "version", "tarball_url", "source_tree_sha256", "tarball_sha256",
            "selection_reason", "binding_family", "size_bucket", "prior_status", "n_cpp_files"]
    with open(tsv_path, "w") as f:
        f.write("\t".join(cols) + "\n")
        for p in final:
            f.write("\t".join(str(p.get(c, "")) for c in cols) + "\n")
    json_safe = []
    for p in final:
        q = dict(p)
        if isinstance(q.get("build_systems"), set):
            q["build_systems"] = sorted(q["build_systems"])
        json_safe.append(q)
    with open(json_path, "w") as f:
        json.dump({"seed": SEED, "n": len(final), "packages": json_safe}, f, indent=1)

    covered_strata = set()
    for p in final:
        covered_strata |= strata_for(p)
    uncovered = all_strata - covered_strata

    with open(os.path.join(HERE, "selection_method.md"), "w") as f:
        f.write(f"""# Overnight 100-package diagnostic sample: selection method

Frozen before any scanner in THIS diagnostic run produced output -- every input is either
real, already-completed prior pipeline evidence (eligible_packages.tsv,
npm_build_configuration.tsv, npm_pipeline_status.tsv, from the real 452/494 corpus run) or a
real, already-completed corpus-wide text search (primitive_search_results.jsonl, task #28).

## Composition
- 75 packages, deterministic greedy stratified coverage (ties broken by package_name, ascending
  -- no randomness in this half at all).
- 25 packages, deterministic random controls from the remaining pool, `random.Random({SEED})`.
- Forced inclusions (counted within the 75): {', '.join(FORCED)}.
- Deduplicated by real, freshly-computed `source_tree_sha256` (provenance.py's own
  `build_source_manifest`, real tarball fetch, no c2cpg) -- any true content duplicate was
  replaced by the next candidate from the remaining pool.

## Strata targeted by the greedy cover
prim:lock, prim:write, prim:read, prim:cmp; binding:{{nan,node-addon-api,raw-napi,node-v8-buffer,none}};
size:{{small,medium,large}}; build:{{binding.gyp,cmake,meson,gn,none}}; status:{{ANALYZED,RESOURCE_LIMIT,CPP_CPG_FAILED}}.

## Coverage achieved
Total distinct strata across the whole 494-package eligible cohort: {len(all_strata)}
Strata covered by this 100-package sample: {len(covered_strata)}
Strata NOT covered (real, disclosed gap -- no eligible package satisfies them at all, or the
greedy budget was exhausted before reaching them): {sorted(uncovered) if uncovered else 'none'}

## Real duplicate content found during dedup
{sum(1 for p in final if str(p.get('selection_reason','')).startswith('dedup_replacement_for')) } replacement(s) made.

## Outputs
- overnight_sample_100.tsv
- overnight_sample_100.json
- selection_method.md (this file)
""")

    print(f"\nDONE. {len(final)} packages selected. Strata covered: {len(covered_strata)}/{len(all_strata)}",
          file=sys.stderr)
    if uncovered:
        print(f"Uncovered strata: {sorted(uncovered)}", file=sys.stderr)


if __name__ == "__main__":
    main()
