#!/usr/bin/env python3
"""NAN-DEDUP-TASK3: real cross-package deduplication for nan_findings' own reportable
candidates, for the specific case direct instruction named -- "deduplicate node-snap7 from
node-snap7-micro-client if both contain identical source."

WHY THIS IS A SEPARATE MECHANISM FROM vendored_attribution.py's OWN CROSS-PACKAGE DEDUP:
that mechanism (task #31) dedupes VENDORED third-party source bundled byte-identically by
several DIFFERENT packages (e.g. re2's own bundled abseil-cpp) -- gated on
`provenance.provenance_hint == "VENDORED_HINT"`. node-snap7's own `src/node_snap7_client.cpp`
is PACKAGE-OWNED, not vendored (`provenance_hint == "PACKAGE_OWNED_HINT"`) -- it is the SAME
real S7Client codebase republished under a SECOND, independent npm identity
(`node-snap7-micro-client`), not a third-party library either package bundles. This is a
different real relationship (same-source-two-package-identities, not
one-package-bundles-a-third-party-library), so it needs its own, narrow, disclosed key -- never
reusing `extract_vendored_library_id()`, which only ever matches `provenance.VENDOR_PATH_
MARKERS` and would correctly return (None, None) for this case (node-snap7's own source is not
under any vendor marker).

REAL EVIDENCE THIS KEY IS BUILT FROM (see `study/nan_capability/NODE_SNAP7_DEDUP_REVIEW.md` for
the full account): node-snap7@1.0.9 and node-snap7-micro-client@0.1.0's own `src/
node_snap7_client.cpp` were fetched directly (hash-verified against each package's own real npm
`shasum`) and diffed byte-for-byte. The two files are NOT byte-identical as WHOLE FILES (they
differ by one trivial, unrelated line -- `FullUpload`'s own buffer-allocation statement is
reordered/inlined, a semantically-equivalent but textually different edit elsewhere in the
file) -- so a WHOLE-FILE `provenance.content_hash` match (the key vendored_attribution.py's own
dedup already uses for the VENDORED case) would fail to dedupe ANY of the three real findings,
including the two (`ReadArea`, `Upload`) whose own relevant code is completely untouched by
that edit. Directly confirmed instead: each finding's own `acquisition_code` (the captured
`Nan::NewBuffer(...)` call text) is BYTE-IDENTICAL between the two files for all three methods.
`method_name` alone is not a safe key either (all three real findings in node-snap7 share the
exact same `acquisition_code` text, `Nan::NewBuffer(bufferData, size, S7Client::FreeCallback,
NULL)` -- the buffer-construction idiom is generic across all three call sites) -- so the real,
disclosed key is the PAIR `(contract_id, method_name, acquisition_code)`: precise enough to
distinguish node-snap7's own 3 real sites from each other, coarse enough to still match the
same real site republished under a second package identity.

SCOPE, disclosed: only `nan_findings` entries with `reportable=True` are considered (an
abstention has no dedup value -- two packages independently failing to resolve a JS call for
the same site is not a fact worth collapsing). This module does not decide reportability itself
(same discipline as `vendored_attribution.py`) -- it only reports which real reportable
candidates, across however many records are passed in, share the same real underlying site.
"""


def cross_package_dedup_key(finding):
    """(contract_id, method_name, acquisition_code) -- see module docstring for why this
    triple, not provenance.content_hash (too coarse -- a whole-file hash, and this real pair's
    two files are NOT byte-identical) and not method_name alone (too coarse the OTHER way --
    node-snap7's own 3 real sites share one acquisition_code text)."""
    return (finding.get("contract_id"), finding.get("method_name"), finding.get("acquisition_code"))


def dedup_nan_reportable(records):
    """Cross-package dedup over a whole run's worth of records (each already carrying
    `nan_findings`, `package_name`). Returns {dedup_key: {"contract_id", "method_name",
    "sample_acquisition_code", "packages": [sorted, unique package names], "raw_exposure_count"}}
    -- `raw_exposure_count` is how many (package, finding) pairs mapped to this key before
    dedup, `len(result)` is the deduplicated count. Never mutates its input."""
    out = {}
    for record in records:
        pkg = record.get("package_name")
        for f in record.get("nan_findings") or []:
            if not f.get("reportable"):
                continue
            key = cross_package_dedup_key(f)
            entry = out.setdefault(key, {
                "contract_id": f.get("contract_id"), "method_name": f.get("method_name"),
                "sample_acquisition_code": f.get("acquisition_code"),
                "packages": set(), "raw_exposure_count": 0,
            })
            entry["packages"].add(pkg)
            entry["raw_exposure_count"] += 1
    for entry in out.values():
        entry["packages"] = sorted(entry["packages"])
    return out
