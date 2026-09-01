#!/usr/bin/env python3
"""Stable adjudication key for a ReDoS finding record.

Per direct instruction: Joern's own `sink_node_id` is NOT a valid persistent adjudication key on
its own -- node IDs are assigned by the CPG builder and are not guaranteed stable across a rebuild
of the same source (a different Joern/js2cpg version, a different build order, or even a re-run
against byte-identical source can renumber them). A finding record that keys itself off a node ID
alone becomes silently unretrievable the next time facts are regenerated.

The STABLE key is derived instead from facts that are properties of the SOURCE, not the analysis
run: package name, pinned version, canonical source path (package-root-relative), the regex's own
fingerprint (sha256 of the full literal text, delimiters+body+flags, as it appears verbatim in
that source), and the sink call's own line number in that canonical source. All five together
identify "this regex, at this call site, in this exact published package version" independent of
which CPG-builder run produced the evidence.

`sink_node_id` (and any other Joern-run-scoped identifier: a raw TSV row index, a producer-output
node id) is still recorded on every finding record -- as SUPPORTING evidence for that one run,
never as the record's own persistent key.
"""
import hashlib


def make_finding_key(package: str, version: str, canonical_path: str,
                      regex_fingerprint_sha256: str, sink_call_line: int) -> dict:
    """Returns both the human-readable composite key and its derived short hash. Both are
    deterministic functions of the five stable input fields only -- no Joern-run-scoped value
    (node id, TSV row order, CPG build timestamp) enters either."""
    composite = (f"redos-finding::{package}@{version}::{canonical_path}::"
                 f"{regex_fingerprint_sha256}::L{sink_call_line}")
    key_hash = hashlib.sha256(composite.encode("utf-8")).hexdigest()
    return {"composite_key": composite, "key_hash": key_hash, "key_hash_short": key_hash[:16]}


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) != 6:
        print("usage: finding_id.py <package> <version> <canonical_path> "
              "<regex_fingerprint_sha256> <sink_call_line>", file=sys.stderr)
        sys.exit(1)
    package, version, canonical_path, fp, line = sys.argv[1:6]
    print(json.dumps(make_finding_key(package, version, canonical_path, fp, int(line)), indent=2))
