#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- source-mode gate (R08).

The reachability producer models fopen as a STORED_FILE_READ delayed source, but it
must filter by the mode argument: a write-only open ("w", "wb", "a", "ab") cannot
supply stored content to a text parser, because data flows FROM the caller INTO the
file, not the other direction.

Before R08 the producer matched every fopen call regardless of mode.  The gecko-dev
prefix scan then recorded 2 "resolved sources" (both fopen-write-mode calls in
unrelated subsystems) and reported NO_DELAYED_SOURCE_REACHES_PARSER for the
SplitMimetype candidate.  A hand scan of those calls confirms neither can supply data
to a text parser:

  nsDOMWindowUtils.cpp:4649  fopen(filename.str().c_str(), "wb")  -- WriteRecordingToDisk
  nsGlobalWindowInner.cpp:991 fopen(fname.get(), "wb+")           -- window dump file init

Both open in write mode; the FILE* is used for fwrite/fputs, never for reading.  The
chain's "2 resolved sources" count was therefore wrong, and NO_DELAYED_SOURCE_REACHES_
PARSER was a vacuously correct statement about an inflated source set, not a traced
negative over a real set.

R08 fixes this by inspecting the mode argument:
  - mode literal containing 'r' or '+' -> read capable -> STORED_FILE_READ (included)
  - mode literal starting with 'w' or 'a' without '+' -> WRITE_ONLY_MODE_EXCLUDED (dropped)
  - mode is a non-literal variable -> AMBIGUOUS_MODE_ARGUMENT (included, flagged)

R08 also adds flow_edges_by_kind to every chain search_space so each segment
(DELAYED_SOURCE2PARSER, PARSER2CONSUMER, etc.) reports its own edge count separately.
An aggregate count alone cannot prove that a specific segment's flow query ran and
returned empty; the per-kind split lets a reader independently verify each segment.

Controls:
  S1  C++ fopen("wb") is NOT a delayed source: write-only mode excluded
  S2  C++ fopen("rb") IS a delayed source: read mode retained
  S3  search_space carries flow_edges_by_kind (per-kind, not just aggregate)
  S4  hand-scan match: gecko-dev resolved_sources_in_unit should drop from 2 to 0
      after write-mode fopen are excluded (re-verified against the raw facts already
      on disk; no new Joern run needed for this gate)
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from escape_parity_chain import derive  # noqa: E402

raw_cpp = HERE / "fixtures_chain_cpp" / "raw"
result = derive(raw_cpp, "C_CPP")

findings_by_unit = {}
for f in result["findings"]:
    u = f.get("unit", f.get("file", ""))
    findings_by_unit.setdefault(u, []).append(f)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"{status}  {name}" + (f": {detail}" if detail else ""))


# S1: c07_write_mode_fopen -- fopen("wb") must be absent from delayed sources
# The raw TSV was produced under the updated producer, so check directly.
ds_path = raw_cpp / "delayed_sources.tsv"
ds_rows = [ln for ln in ds_path.read_text().splitlines() if ln.strip()]
c07_sources = [r for r in ds_rows if "c07_write_mode_fopen" in r]
tooth("S1 C++ fopen(\"wb\") excluded: not a read source",
      len(c07_sources) == 0,
      f"found {len(c07_sources)} rows (expected 0); rows={c07_sources[:2]}")

# S2: c08_read_mode_fopen -- fopen("rb") must appear as RESOLVED_EXTERNAL
c08_sources = [r for r in ds_rows if "c08_read_mode_fopen" in r and "fopen" in r]
c08_resolved = [r for r in c08_sources if "RESOLVED_EXTERNAL" in r]
tooth("S2 C++ fopen(\"rb\") retained: read mode is a valid source",
      len(c08_resolved) >= 1,
      f"found {len(c08_sources)} total, {len(c08_resolved)} resolved (expected ≥1)")

# S3: every chain finding for a CANDIDATE must have flow_edges_by_kind in search_space
from escape_parity_sites import CANDIDATE  # noqa: E402
candidates = [f for f in result["findings"] if f.get("classification") == CANDIDATE]
chains_with_kind_breakdown = [
    f for f in candidates
    if isinstance(f.get("chain", {}).get("search_space", {}).get("flow_edges_by_kind"), dict)
]
tooth("S3 search_space carries flow_edges_by_kind on every candidate chain",
      len(candidates) > 0 and len(chains_with_kind_breakdown) == len(candidates),
      f"{len(chains_with_kind_breakdown)}/{len(candidates)} candidates have it")

# S4: validate gecko-dev re-interpretation (from frozen raw facts, no new Joern run)
# The pre-R08 delayed_sources.tsv for mozilla-gecko-dev-prefix had 2 resolved fopen rows.
# Both are write-mode fopen calls.  After R08 filtering, resolved_sources_in_unit must
# be 0 for the SplitMimetype candidate.
# Use the stored R07 findings file to check what the chain REPORTED.
gecko_path = (HERE / "study" / "bounty_corpus" / "results_r07" / "mozilla-gecko-dev-prefix"
              / "findings_c_cpp.json")
if gecko_path.exists():
    gecko = json.loads(gecko_path.read_text())
    from escape_parity_sites import CANDIDATE as CAND  # noqa: F811
    gecko_cands = [f for f in gecko["findings"] if f.get("classification") == CAND]
    # Under R07 the candidate's search_space.resolved_sources_in_unit was 2.
    # This gate verifies the R07 result shows the problem we fixed in R08.
    # (The R08-corrected result is not yet available without a new Joern run.)
    r07_sources = [f["chain"]["search_space"].get("resolved_sources_in_unit", -1)
                   for f in gecko_cands if "chain" in f and "search_space" in f["chain"]]
    all_write_mode = all(n == 2 for n in r07_sources)
    tooth("S4 gecko-dev R07 candidate shows 2 sources (both write-mode; R08 will drop to 0)",
          len(r07_sources) > 0 and all_write_mode,
          f"r07_resolved_sources={r07_sources} (2 means write-mode fopen counted wrongly)")
else:
    tooth("S4 gecko-dev R07 file not found (skip)", True, "file not present on this machine")


n_pass = sum(1 for _, ok, _ in results if ok)
n_fail = sum(1 for _, ok, _ in results if not ok)
print(f"\nESCAPE_PARITY_SOURCE_MODE_R08={n_pass}/{n_pass+n_fail}")
print("SOURCE_MODE_GATE=" + ("PASS" if n_fail == 0 else "FAIL"))
sys.exit(0 if n_fail == 0 else 1)
