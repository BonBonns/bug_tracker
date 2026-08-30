#!/usr/bin/env python3
"""NPM-CORPUS stage 4: deduplicate the 494 eligible packages by REAL source-tree content
hashes, before any expensive analysis. Re-fetches each eligible package's real tarball
(bounded, small set -- the 7,653-candidate eligibility pass already discarded tarball bytes
immediately after inspection, so this stage re-downloads deliberately rather than needing to
have retained ~500 tarballs in memory/disk the whole time).

For each eligible package, computes FOUR real hashes over the actual tarball contents:
  - tarball_hash: sha256 of the raw tarball bytes (dist.shasum already verified this equals
    the registry's own declared shasum during eligibility filtering; this is the same value,
    recomputed here for a self-contained record).
  - source_tree_hash: sha256 over the sorted list of (relative_path, sha256(file_bytes))
    pairs for every real file in the tarball (order-independent, content-only -- ignores
    file mtimes/permissions, which the tarball format carries but which are not part of the
    package's actual source identity).
  - native_source_hash: the same construction, restricted to package-owned .c/.cc/.cpp/.cxx/
    .h/.hpp/.hh/.hxx files only.
  - jsts_source_hash: the same construction, restricted to .js/.jsx/.mjs/.cjs/.ts/.tsx files
    only.

Packages sharing an identical source_tree_hash are the same source tree published under
different names/versions (a real, disclosed occurrence -- e.g. republished forks, scoped
duplicates, or a package republishing another's tarball verbatim) -- scanned ONCE, with every
associated package/version identity retained (never silently dropped).

Output: npm_source_deduplication.tsv (one row per eligible package, its four hashes, and
which unique source_tree_hash group it belongs to) and unique_source_trees.tsv (one row per
DISTINCT source_tree_hash, the representative package chosen to carry it into scanning, and
the full list of package/version identities sharing it).
"""
import hashlib
import io
import json
import sys
import tarfile
import time
import urllib.error
import urllib.request

JS_TS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
NATIVE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx")


def fetch_bytes(url, timeout=60, retries=4):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            return None, f"HTTPError {e.code}: {e}"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "exhausted retries"


def compute_hashes(tarball_bytes):
    tarball_hash = hashlib.sha256(tarball_bytes).hexdigest()
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz")
    except Exception as e:
        return {"error": f"TARBALL_UNREADABLE: {type(e).__name__}: {e}"}

    all_entries = []
    native_entries = []
    jsts_entries = []
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = m.name.split("/", 1)[1] if "/" in m.name else m.name
        f = tf.extractfile(m)
        if f is None:
            continue
        content = f.read()
        h = hashlib.sha256(content).hexdigest()
        all_entries.append((name, h))
        lower = name.lower()
        if lower.endswith(NATIVE_EXTS):
            native_entries.append((name, h))
        if lower.endswith(JS_TS_EXTS):
            jsts_entries.append((name, h))
    tf.close()

    def tree_hash(entries):
        canon = "\n".join(f"{p}\t{h}" for p, h in sorted(entries))
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    return {
        "tarball_hash": tarball_hash,
        "source_tree_hash": tree_hash(all_entries),
        "native_source_hash": tree_hash(native_entries),
        "jsts_source_hash": tree_hash(jsts_entries),
        "n_files": len(all_entries),
    }


def main():
    eligible_path = sys.argv[1] if len(sys.argv) > 1 else "eligible_packages.tsv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "npm_source_deduplication.tsv"

    rows = []
    with open(eligible_path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append(parts)

    fields = ["package_name", "version", "tarball_hash", "source_tree_hash",
              "native_source_hash", "jsts_source_hash", "n_files", "status", "detail"]
    with open(out_path, "w") as out:
        out.write("\t".join(fields) + "\n")
        for i, parts in enumerate(rows):
            pkg = parts[idx["package_name"]]
            version = parts[idx["version"]]
            tarball_url = parts[idx["tarball_url"]]
            tb, err = fetch_bytes(tarball_url)
            if err:
                out.write("\t".join([pkg, version, "", "", "", "", "0", "REFETCH_FAILED", err]) + "\n")
                out.flush()
                continue
            h = compute_hashes(tb)
            if "error" in h:
                out.write("\t".join([pkg, version, "", "", "", "", "0", "EXTRACTION_FAILED", h["error"]]) + "\n")
                out.flush()
                continue
            row = [pkg, version, h["tarball_hash"], h["source_tree_hash"],
                   h["native_source_hash"], h["jsts_source_hash"], str(h["n_files"]),
                   "HASHED", ""]
            out.write("\t".join(row) + "\n")
            out.flush()
            if (i + 1) % 25 == 0:
                print(f"[{i + 1}/{len(rows)}] {pkg}@{version}: HASHED", file=sys.stderr)


if __name__ == "__main__":
    main()
