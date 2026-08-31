#!/usr/bin/env python3
"""NAN-PREVALENCE-STUDY step 2: heuristic input-origin classification from the captured
25-line context windows in nan_prevalence_hits.tsv -- NOT a re-read of full source, NOT a
CPG dataflow trace. This is explicitly a first-pass triage heuristic to shape the prevalence
table's origin breakdown; every site this study's write-up cites as evidence for a specific
claim (about node-snap7, or about the chosen next capability) is separately confirmed by
direct full-file source reading, the same discipline as R05_INTERIM_NEAR_MISS_AUDIT.md.

Heuristic (disclosed, not a dataflow proof):
  JS_ARGUMENT_CANDIDATE      -- window contains a CallbackInfo/Nan info-style accessor
                                 (`info[`, `args[`) -- i.e. this call is plausibly reachable
                                 from a JS-callback context; does NOT itself prove the size
                                 argument traces to that accessor (that needs a real read).
  EXTERNAL_NETWORK_CANDIDATE -- window contains socket/protocol/client-server vocabulary
                                 suggesting the size traces to a network peer, not JS.
  NATIVE_INTERNAL_CANDIDATE  -- neither signal present, and the window shows a literal,
                                 sizeof(), or purely struct-internal size computation.
  UNRESOLVED                 -- neither signal present and the size's origin is not evident
                                 from the captured window alone (would need the full file).
A window can trip BOTH the JS and NETWORK signals (e.g. node-snap7's own case: a JS-callback
function whose data ultimately comes from a network read) -- both are recorded, not collapsed,
because the two questions ("is this reachable from JS" and "does the SIZE come from a JS
argument") are exactly the ones Phase B's promotion boundary already treats as distinct.
"""
import csv
import re
from collections import defaultdict, Counter

JS_ACCESSOR = re.compile(r"\b(info|args)\s*\[")
NETWORK_TOKENS = re.compile(
    r"\b(recv|socket|Socket|libcurl|curl_|inet_|bind\(|accept\(|Client->|Server->|"
    r"->Read\(|ReadArea|ReadSZL|Upload|Download|s7client|s7server|snap7|"
    r"NetworkStream|TcpSocket|udp_|tcp_)\b"
)
NATIVE_LITERAL = re.compile(r"=\s*(sizeof\s*\(|0x[0-9a-fA-F]+|\d+)\s*[,;)]")


def classify(context):
    tags = []
    if JS_ACCESSOR.search(context):
        tags.append("JS_ARGUMENT_CANDIDATE")
    if NETWORK_TOKENS.search(context):
        tags.append("EXTERNAL_NETWORK_CANDIDATE")
    if not tags:
        if NATIVE_LITERAL.search(context):
            tags.append("NATIVE_INTERNAL_CANDIDATE")
        else:
            tags.append("UNRESOLVED")
    return tags


def main():
    rows = []
    with open("nan_prevalence_hits.tsv", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            row["origin_tags"] = classify(row["context"])
            rows.append(row)

    with open("nan_prevalence_origin_classified.tsv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "package_name", "version", "family", "file", "line", "matched_text",
            "origin_tags"], delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({**r, "origin_tags": ";".join(r["origin_tags"])})

    # per-family origin distribution (by CALL SITE, then by unique PACKAGE)
    fam_tag_sites = defaultdict(Counter)
    fam_tag_pkgs = defaultdict(lambda: defaultdict(set))
    for r in rows:
        for t in r["origin_tags"]:
            fam_tag_sites[r["family"]][t] += 1
            fam_tag_pkgs[r["family"]][t].add(r["package_name"])

    print("=== per-family origin distribution (call sites) ===")
    for fam in sorted(fam_tag_sites):
        print(f"\n{fam}:")
        for tag, n in fam_tag_sites[fam].most_common():
            print(f"  {tag:28s} sites={n:4d}  packages={len(fam_tag_pkgs[fam][tag]):3d}")


if __name__ == "__main__":
    main()
