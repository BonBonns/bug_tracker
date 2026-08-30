#!/usr/bin/env python3
"""NPM-CORPUS registry-wide enumeration (REGISTRY_ENUMERATION discovery provenance): walks
the ENTIRE public npm registry via the CouchDB-compatible `_all_docs` interface
(`https://replicate.npmjs.com/registry/_all_docs`), checkpointed, key-based pagination,
resumable.

Real, confirmed constraints of this specific public endpoint (tested directly before writing
this script, not assumed): `include_docs=true` and `update_seq=true` are both REJECTED
("Bad Request") -- this replica only serves plain id+rev pairs via `_all_docs`, no bulk
document fetch and no per-request update_seq. Snapshot `update_seq` and `doc_count` are
instead read once from the registry root (`GET /registry/`, confirmed working: returns
`{"db_name":"registry","doc_count":<N>,"update_seq":<N>}`) and recorded as this run's
snapshot metadata -- not per-page, since the endpoint won't provide it per-page.

Pagination: CouchDB `_all_docs` is sorted by key (package name). Each page requests
`startkey=<last key from previous page, JSON-quoted>&limit=<PAGE_SIZE>`; `startkey` is
INCLUSIVE, so the first row of every page after the first is the same key as the last row of
the previous page and is skipped on write (real, confirmed behavior -- verified directly:
requesting `startkey="X"` returns X as the first row). No `skip=N` is used at any point
(CouchDB's own documented behavior: `skip` at large offsets requires internally walking N
rows, becoming increasingly slow; key-based `startkey` pagination avoids this entirely).

Output: append-only working file `registry_ids.tsv` (package name, rev, page number, since
row-flush order is checkpoint-relevant) plus a resumable state file `registry_ids_state.json`
recording: total_rows (as first reported by the API), doc_count/update_seq (from the root
endpoint, this run's snapshot metadata), rows_written, last_key, page_count, retry_count,
completed (bool). On restart, reads state.json and resumes from last_key -- never re-walks
from the beginning, never silently drops rows already written.

This script does NOT itself apply any prefilter -- it is a pure, complete id+rev walk of the
registry. Metadata prefiltering (item 3's "documented high-recall metadata prefilter") is a
SEPARATE, later stage (`prefilter_registry.py`) that consumes this file incrementally.
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REGISTRY_ALLDOCS = "https://replicate.npmjs.com/registry/_all_docs"
REGISTRY_ROOT = "https://replicate.npmjs.com/registry/"
PAGE_SIZE = 1000


def fetch_json(url, retries=6, timeout=30):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8")), 0
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(min(2 ** attempt * 2, 60))
                continue
            return None, attempt + 1
        except Exception:
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 30))
                continue
            return None, attempt + 1
    return None, retries


def load_state(state_path):
    try:
        with open(state_path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_state(state_path, state):
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    import os
    os.replace(tmp, state_path)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "registry_ids.tsv"
    state_path = sys.argv[2] if len(sys.argv) > 2 else "registry_ids_state.json"

    state = load_state(state_path)
    if state is None:
        root, root_retries = fetch_json(REGISTRY_ROOT)
        if root is None:
            print("FATAL: could not fetch registry root metadata", file=sys.stderr)
            sys.exit(1)
        state = {
            "snapshot_doc_count": root.get("doc_count"),
            "snapshot_update_seq": root.get("update_seq"),
            "total_rows": None,
            "rows_written": 0,
            "last_key": None,
            "page_count": 0,
            "retry_count": root_retries,
            "completed": False,
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        save_state(state_path, state)
        out_mode = "w"
    else:
        out_mode = "a"

    if state.get("completed"):
        print(f"Already completed: {state['rows_written']} rows, last_key={state['last_key']!r}",
              file=sys.stderr)
        return

    with open(out_path, out_mode) as out:
        if out_mode == "w":
            out.write("package_name\trev\tpage_number\n")

        while not state["completed"]:
            if state["last_key"] is None:
                url = f"{REGISTRY_ALLDOCS}?limit={PAGE_SIZE}"
            else:
                url = f"{REGISTRY_ALLDOCS}?limit={PAGE_SIZE}&startkey={urllib.parse.quote(json.dumps(state['last_key']))}"
            data, retries = fetch_json(url)
            state["retry_count"] += retries
            if data is None:
                print(f"FATAL: page fetch failed after retries at last_key={state['last_key']!r}",
                      file=sys.stderr)
                save_state(state_path, state)
                sys.exit(1)

            if state["total_rows"] is None:
                state["total_rows"] = data.get("total_rows")

            rows = data.get("rows", [])
            skip_first = state["last_key"] is not None
            written_this_page = 0
            for i, row in enumerate(rows):
                if skip_first and i == 0:
                    continue  # startkey is inclusive -- this row was already written
                name = row.get("id", "")
                rev = row.get("value", {}).get("rev", "")
                out.write(f"{name}\t{rev}\t{state['page_count']}\n")
                state["last_key"] = name
                written_this_page += 1
            out.flush()

            state["rows_written"] += written_this_page
            state["page_count"] += 1
            if written_this_page == 0 or len(rows) < PAGE_SIZE:
                state["completed"] = True
            save_state(state_path, state)

            if state["page_count"] % 20 == 0 or state["completed"]:
                print(f"page {state['page_count']}: rows_written={state['rows_written']} "
                      f"/ total_rows={state['total_rows']} last_key={state['last_key']!r}",
                      file=sys.stderr)
            time.sleep(0.05)  # polite pacing -- this is a bulk, cheap endpoint, still shared infra

    print(f"DONE: {state['rows_written']} rows written, {state['page_count']} pages, "
          f"{state['retry_count']} total retries", file=sys.stderr)


if __name__ == "__main__":
    main()
