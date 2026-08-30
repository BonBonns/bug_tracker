#!/usr/bin/env python3
"""NPM-CORPUS candidate discovery, stage 2a: builds a REAL, reproducible candidate name list
via the npm registry's public search API (`registry.npmjs.org/-/v1/search`), unioned across a
fixed set of native-addon indicator query terms.

Disclosed method and its real, honest scope limit: this is NOT a full crawl of the npm
registry (~3-4M packages), which is not feasible to enumerate row-by-row and individually
inspect within this environment's real time/compute/disk budget. The search API performs
relevance-ranked full-text search over name/description/keywords/README, not a structured
dependency filter -- there is no public, unauthenticated npm API for "list all packages
depending on X" at registry scale. The candidate list this script produces is therefore the
union of packages the registry's own search surfaces for a fixed, recorded set of real
indicator terms (queried at `size=250` per page, the API's real per-page maximum, paginated
up to each query's own total or a bounded cutoff, whichever is smaller) -- reproducible by
re-running this exact script with the same QUERY_TERMS list, not a claim of registry-wide
completeness. Every eligible package this later surfaces still goes through REAL, individual
eligibility verification (downloaded tarball, real file listing) before being counted --
this stage only casts the net; it does not itself decide eligibility.

This script's output is labeled `discovery_provenance = REGISTRY_RELEVANCE_SEARCH` and is
referred to elsewhere in this corpus as the **SEARCH_DERIVED_CANDIDATE_COHORT** -- a
real, reproducible, but coverage-BOUNDED pre-filter candidate list, explicitly NOT a pinned
npm universe manifest (item 2 of the corpus-phase instruction) and NOT comparable in any way
to a post-eligibility-filter reference count (this cohort is pre-filter; any such count is
post-filter -- similar magnitude between the two proves nothing about coverage and must never
be cited as validation). See `enumerate_registry.py` for the complementary
`REGISTRY_ENUMERATION`-provenance discovery method (CouchDB `_all_docs` walk +
metadata prefilter) this cohort is unioned with before item 2's manifest is frozen; see
`CORPUS_STATUS.md` for the current, authoritative status of that union.

Output: candidates.tsv (package name, discovery query, npm search score/popularity fields
returned by the API) -- one row per (package, query) pair; downstream dedup by package name.
"""
import json
import sys
import time
import urllib.request
import urllib.error

QUERY_TERMS = [
    "node-addon-api", "napi native addon", "n-api native", "node-gyp binding",
    "nan native addon", "prebuild-install", "node-pre-gyp", "cmake-js native",
    "native addon binding.gyp", "napi module native",
]

PAGE_SIZE = 250
MAX_PER_QUERY = 2000  # bounded cutoff per query term -- disclosed, not registry-exhaustive
BASE = "https://registry.npmjs.org/-/v1/search"


def search_page(text, from_, size):
    url = f"{BASE}?text={urllib.parse.quote(text)}&size={size}&from={from_}"
    req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


import urllib.parse  # noqa: E402  (kept near use for clarity)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "candidates.tsv"
    seen = {}  # name -> set of queries that surfaced it
    total_fetched = 0
    with open(out_path, "w") as out:
        out.write("package_name\tdiscovery_query\tscore_final\tpopularity\tquality\tmaintenance\tversion\tdate\n")
        for term in QUERY_TERMS:
            from_ = 0
            term_total = None
            while from_ < MAX_PER_QUERY:
                try:
                    data = search_page(term, from_, PAGE_SIZE)
                except urllib.error.HTTPError as e:
                    print(f"HTTPError {e.code} on query {term!r} from={from_}: {e}", file=sys.stderr)
                    break
                except Exception as e:
                    print(f"Error on query {term!r} from={from_}: {e}", file=sys.stderr)
                    break
                objs = data.get("objects", [])
                term_total = data.get("total", 0)
                if not objs:
                    break
                for o in objs:
                    pkg = o.get("package", {})
                    name = pkg.get("name")
                    if not name:
                        continue
                    score = o.get("score", {})
                    detail = score.get("detail", {})
                    row = [
                        name, term,
                        str(score.get("final", "")),
                        str(detail.get("popularity", "")),
                        str(detail.get("quality", "")),
                        str(detail.get("maintenance", "")),
                        pkg.get("version", ""),
                        pkg.get("date", ""),
                    ]
                    out.write("\t".join(row) + "\n")
                    seen.setdefault(name, set()).add(term)
                    total_fetched += 1
                from_ += PAGE_SIZE
                if from_ >= term_total:
                    break
                time.sleep(0.15)  # polite pacing against the public registry API
            print(f"query {term!r}: registry total={term_total}, fetched up to "
                  f"{min(from_, MAX_PER_QUERY)}", file=sys.stderr)
    print(f"TOTAL rows written: {total_fetched}", file=sys.stderr)
    print(f"UNIQUE package names discovered: {len(seen)}", file=sys.stderr)


if __name__ == "__main__":
    main()
