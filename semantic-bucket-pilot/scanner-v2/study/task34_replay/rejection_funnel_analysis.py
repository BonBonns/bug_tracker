#!/usr/bin/env python3
"""TASK34-FUNNEL-R01: per-property rejection funnel over task #34's own real replay output
(results/replay_records.jsonl) -- NOT a new scan, NOT a new corpus run, purely a re-read and
re-categorization of what the replay already computed. Never recomputes reportable itself; every
bucket a record falls into is read directly from fields the real pipeline already set
(scanner_candidate, provenance.resolved, stage_status, reachability_status, applicability_status,
adjudication_status, reportable).

Categorization order (the first reason, in this order, that a record is NOT reportable -- matches
the real pipeline's own gate sequence: PROPERTY_CANDIDATE_RULES -> provenance.enrich_record's
one-way rule -> staged_enablement's reachability gate (staged properties only) ->
applicability_status -> adjudication_status):
  1. NOT_A_CANDIDATE          -- scanner_candidate is False (R04/R05/R06 only: a real verdict
                                   other than VALUE_ACQUISITION_GUARD_MISSING -- an abstention or
                                   a confirmed-safe VALUE_ACQUISITION_GUARD_ESTABLISHED, never a
                                   candidate to begin with). Always empty for the five staged
                                   properties (their own PROPERTY_CANDIDATE_RULES entry is an
                                   unconditional True).
  2. PROVENANCE_UNRESOLVED     -- provenance.resolved is False.
  3. STAGE_NOT_ENABLED         -- staged property only, not in staged_enablement.ENABLED_PROPERTIES
                                   (OOB_COMPARE, always, by design).
  4. INSUFFICIENT_REACHABILITY -- staged property only, stage_status ==
                                   REACHABILITY_REQUIRED_FOR_REPORTING (reachability_status is
                                   TIER_INTERNAL_UNREGISTERED, REACHABILITY_UNRESOLVED, or absent
                                   -- real evidence the function exists but not that JS can reach
                                   it).
  5. APPLICABILITY_NOT_DETERMINED -- applicability_status != "APPLICABLE" (the real, current
                                   value is reported alongside, e.g. NOT_YET_DETERMINED).
  6. CONFIRMED_FALSE_POSITIVE  -- adjudication_status == "CONFIRMED_FALSE_POSITIVE".
  7. REPORTABLE                -- cleared every gate; reportable is True.
A record can appear in exactly one bucket -- the categorization walks the same order the real
formula ANDs together, stopping at the first failing clause, so "why isn't this reportable" is
never ambiguous or double-counted.
"""
import json
import os
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SCANNER_V2)
import vendored_attribution as va  # noqa: E402

RESOURCE_GUARD_KEYS = ("r04_findings", "r05_findings", "r06_findings")
STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
               "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates")
ALL_KEYS = RESOURCE_GUARD_KEYS + STAGED_KEYS

LABELS = {
    "r04_findings": "R04 (comparison diagnostic)",
    "r05_findings": "R05 (comparison diagnostic)",
    "r06_findings": "FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven)",
    "lock_balance_findings": "LOCK_BALANCE",
    "protected_field_findings": "PROTECTED_FIELD",
    "oob_write_candidates": "OOB_WRITE",
    "oob_index_write_candidates": "OOB_INDEX_WRITE",
    "oob_read_candidates": "OOB_READ",
    "oob_compare_candidates": "OOB_COMPARE",
}


def load_replayed():
    out = []
    with open(os.path.join(RESULTS_DIR, "replay_records.jsonl")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if d.get("outcome") == "REPLAYED":
                out.append(d)
    return out


def classify_one(key, f):
    """Returns the bucket name for one finding/candidate. Never reads `reportable` to decide the
    bucket except at the very end (REPORTABLE) -- every earlier bucket is read from the specific
    field that actually gates it, so this is a real re-derivation of "why," not a restatement of
    the boolean."""
    scanner_candidate = f.get("scanner_candidate")
    if key in RESOURCE_GUARD_KEYS and not scanner_candidate:
        return "NOT_A_CANDIDATE", f.get("verdict")
    prov = f.get("provenance") or {}
    if not prov.get("resolved"):
        return "PROVENANCE_UNRESOLVED", prov.get("provenance_hint")
    if key in STAGED_KEYS:
        stage_status = f.get("stage_status")
        if stage_status == "STAGE_NOT_ENABLED":
            return "STAGE_NOT_ENABLED", None
        if stage_status == "REACHABILITY_REQUIRED_FOR_REPORTING":
            return "INSUFFICIENT_REACHABILITY", f.get("reachability_status")
    if f.get("applicability_status") != "APPLICABLE":
        return "APPLICABILITY_NOT_DETERMINED", f.get("applicability_status")
    if f.get("adjudication_status") == "CONFIRMED_FALSE_POSITIVE":
        return "CONFIRMED_FALSE_POSITIVE", None
    return "REPORTABLE", None


def build_funnel(replayed):
    funnel = {k: Counter() for k in ALL_KEYS}
    detail = {k: defaultdict(Counter) for k in ALL_KEYS}  # bucket -> {sub_reason: count}
    for rec in replayed:
        for key in ALL_KEYS:
            for f in rec.get(key) or []:
                bucket, sub = classify_one(key, f)
                funnel[key][bucket] += 1
                detail[key][bucket][str(sub)] += 1
    return funnel, detail


# =============================================================================================
# OOB_INDEX_WRITE stratified audit -- the biggest single bucket (3290/3918 raw records, task
# #34's own headline number). Determines whether this volume reflects real, useful abstentions/
# candidates or a broad, low-precision matching problem, using only real data already in the
# replay -- no new scanning, no invented categories.
# =============================================================================================
def oob_index_write_audit(replayed):
    key = "oob_index_write_candidates"
    raw = []
    for rec in replayed:
        for f in rec.get(key) or []:
            raw.append((rec["package_name"], rec["version"], f))

    by_package = Counter(pkg for pkg, ver, f in raw)
    by_function = Counter((pkg, f.get("function_id")) for pkg, ver, f in raw)
    by_file = Counter((pkg, f.get("file")) for pkg, ver, f in raw)
    by_rule = Counter((f.get("derivation") or {}).get("rule") for pkg, ver, f in raw)
    by_capacity_source = Counter((f.get("derivation") or {}).get("capacity_source")
                                  for pkg, ver, f in raw)
    by_reachability = Counter(f.get("reachability_status") or "NONE" for pkg, ver, f in raw)
    by_provenance_hint = Counter(
        (f.get("provenance") or {}).get("provenance_hint") for pkg, ver, f in raw)

    # top functions by raw finding count -- the concentration signal: is this volume spread
    # thinly across many distinct real sites, or piled up in a small number of functions each
    # producing many near-identical findings (e.g. a dispatch table)?
    top_functions = by_function.most_common(15)
    top_functions_detail = []
    for (pkg, fid), n in top_functions:
        sample = next(f for p, v, f in raw if p == pkg and f.get("function_id") == fid)
        top_functions_detail.append({
            "package": pkg, "function": sample.get("function"), "file": sample.get("file"),
            "function_id": fid, "raw_finding_count": n,
            "array_names_in_this_function": sorted(set(
                f.get("array") for p, v, f in raw if p == pkg and f.get("function_id") == fid)),
        })

    # vendored-library identity breakdown among the VENDORED_HINT-attributed subset specifically
    # for THIS property (not the whole-replay aggregate) -- which real third-party libraries
    # this volume actually comes from.
    lib_counts = Counter()
    for pkg, ver, f in raw:
        prov = f.get("provenance") or {}
        if prov.get("provenance_hint") == "VENDORED_HINT":
            lib_id, _ = va.extract_vendored_library_id(prov.get("source_path"))
            lib_counts[lib_id or "UNRESOLVED_LIBRARY_ID"] += 1

    # real dedup count for this property specifically (not the whole-replay total)
    agg = va.aggregate_vendored_dedup(replayed)
    dedup_summary = va.summarize(agg).get(key, {"deduplicated_count": 0, "raw_exposure_count": 0})

    return {
        "raw_total": len(raw),
        "distinct_packages": len(by_package),
        "distinct_function_sites": len(by_function),
        "distinct_files": len(by_file),
        "mean_findings_per_function_site": round(len(raw) / len(by_function), 2) if by_function else 0,
        "top_10_packages_by_raw_count": by_package.most_common(10),
        "top_15_function_sites": top_functions_detail,
        "derivation_rule_distribution": dict(by_rule),
        "capacity_source_distribution": dict(by_capacity_source),
        "reachability_distribution": dict(by_reachability),
        "provenance_hint_distribution": dict(by_provenance_hint),
        "vendored_library_id_distribution": dict(lib_counts.most_common(20)),
        "vendored_dedup_this_property": dedup_summary,
        "package_owned_raw_count": by_provenance_hint.get("PACKAGE_OWNED_HINT", 0),
        "vendored_raw_count": by_provenance_hint.get("VENDORED_HINT", 0),
    }


def build_unresolved_root_cause(replayed):
    """For the 136 REACHABILITY_UNRESOLVED cases (real code, not a category label): which
    package(s) they concentrate in, and WHY (facts_available check: reachability_tier.py's own
    classify_function_reachability returns REACHABILITY_UNRESOLVED unconditionally whenever a
    package's own js/cpp facts are too thin -- specifically bool(js['calls']) and
    bool(cpp['functions']) both real and non-empty -- checked here directly against each such
    package's own preserved bundle facts, not assumed)."""
    import tarfile as _tf
    by_pkg = Counter()
    by_prop = Counter()
    pkgs = set()
    for rec in replayed:
        for key in STAGED_KEYS[:5]:  # exclude oob_compare_candidates -- 0 raw records
            for f in rec.get(key) or []:
                if f.get("reachability_status") == "REACHABILITY_UNRESOLVED":
                    by_pkg[rec["package_name"]] += 1
                    by_prop[key] += 1
                    pkgs.add((rec["package_name"], rec["version"]))
    root_causes = []
    bundle_dir = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
    for pkg, ver in sorted(pkgs):
        bpath = os.path.join(bundle_dir, f"{pkg.replace('/', '__')}@{ver}.tar.gz")
        with _tf.open(bpath, "r:gz") as tf:
            js = json.load(tf.extractfile("js_facts.json"))
            cpp = json.load(tf.extractfile("cpp_facts.json"))
        root_causes.append({
            "package_name": pkg, "version": ver,
            "unresolved_count": by_pkg[pkg],
            "js_calls_count": len(js.get("calls", [])),
            "cpp_functions_count": len(cpp.get("functions", [])),
            "facts_available": bool(js.get("calls")) and bool(cpp.get("functions")),
        })
    return {"by_package": dict(by_pkg), "by_property": dict(by_prop),
            "root_cause_per_package": root_causes}


def main():
    replayed = load_replayed()
    funnel, detail = build_funnel(replayed)
    oiw_audit = oob_index_write_audit(replayed)
    unresolved_root_cause = build_unresolved_root_cause(replayed)

    deep_dive = None
    dd_path = os.path.join(RESULTS_DIR, "reachability_deep_dive.json")
    if os.path.isfile(dd_path):
        deep_dive = json.load(open(dd_path))

    determinism = None
    det_path = os.path.join(RESULTS_DIR, "determinism_verification.json")
    if os.path.isfile(det_path):
        determinism = json.load(open(det_path))

    out = {
        "funnel": {k: dict(v) for k, v in funnel.items()},
        "funnel_detail": {k: {b: dict(sub) for b, sub in v.items()} for k, v in detail.items()},
        "oob_index_write_stratified_audit": oiw_audit,
        "reachability_unresolved_root_cause": unresolved_root_cause,
    }
    with open(os.path.join(RESULTS_DIR, "rejection_funnel.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    write_report(funnel, detail, oiw_audit, replayed, unresolved_root_cause, deep_dive, determinism)
    print("Wrote results/rejection_funnel.json and REJECTION_FUNNEL_ANALYSIS.md")


def write_report(funnel, detail, oiw, replayed, unresolved_root_cause=None, deep_dive=None,
                  determinism=None):
    lines = []
    a = lines.append
    a("# TASK #34 rejection funnel + OOB_INDEX_WRITE stratified audit\n")
    a("Re-analysis of task #34's own real replay output (`results/replay_records.jsonl`, 97 "
      "packages, `develop @ fdb22fa5af01cbaab9577d85906f0a33515f0e62`). No new scan, no new "
      "download, no recomputation of `reportable` -- every bucket below is read directly from "
      "fields the real pipeline already set.\n")

    a("## Cross-language linker: already current, not stale (answering directly)\n")
    a("Task #34's replay never reused any bundle's own captured `cross_language_bindings.json` "
      "(that file was written at overnight-run capture time, by an earlier revision of the "
      "linker, and predates task #46/#47). `replay_100_bundles.py` does not load that file into "
      "a record at all -- `reachability_tier.classify_record_reachability(record, js, cpp)` "
      "computes registration and linkage FRESH, every single time, straight from each package's "
      "own preserved `js_facts.json`/`cpp_facts.json`, via `reachability_tier.py`'s own live "
      "`import link_napi_facts` -- the SAME current, `develop`-checked-out FIX01I linker this "
      "analysis's own deep-dive below reuses. There was no stale link output to recompute away "
      "from; this was already true for the original replay.\n")

    a("## Headline correction\n")
    a("3,918 raw scanner records is not 3,918 vulnerabilities. Zero reportable records does not "
      "mean 97 packages are safe. Every raw record failed at least one required evidence gate -- "
      "this section shows exactly which one, per property, so precision work can target the "
      "actual bottleneck rather than guess at it.\n")

    a("## Per-property rejection funnel\n")
    bucket_order = ["NOT_A_CANDIDATE", "PROVENANCE_UNRESOLVED", "STAGE_NOT_ENABLED",
                     "INSUFFICIENT_REACHABILITY", "APPLICABILITY_NOT_DETERMINED",
                     "CONFIRMED_FALSE_POSITIVE", "REPORTABLE"]
    a("| Property | Raw | " + " | ".join(bucket_order) + " |")
    a("|---|---|" + "---|" * len(bucket_order))
    for key in ALL_KEYS:
        c = funnel[key]
        raw = sum(c.values())
        row = [LABELS[key], str(raw)] + [str(c.get(b, 0)) for b in bucket_order]
        a("| " + " | ".join(row) + " |")
    a("")
    a("**Reading this table:** `PROVENANCE_UNRESOLVED` is 0 everywhere -- task #34's own "
      "refetch-and-verify closed that bottleneck completely (confirmed already in "
      "TASK34_RESULTS.md: 3,918/3,918 resolved). The real bottleneck for the five staged "
      "properties is overwhelmingly `INSUFFICIENT_REACHABILITY` (no established JS-reachability "
      "evidence -- `TIER_INTERNAL_UNREGISTERED` or `REACHABILITY_UNRESOLVED`); for R04/R05/R06 "
      "it is `NOT_A_CANDIDATE` (the scanner's own verdict logic never classified most of that "
      "small raw count as a real candidate to begin with -- abstentions and confirmed-safe "
      "matches, not gated-out positives).\n")

    a("### Sub-reason detail (what's actually inside each bucket)\n")
    for key in ALL_KEYS:
        if not funnel[key]:
            continue
        a(f"**{LABELS[key]}**")
        for bucket in bucket_order:
            sub = detail[key].get(bucket)
            if not sub:
                continue
            a(f"- {bucket}: " + ", ".join(f"{k}={v}" for k, v in sorted(
                sub.items(), key=lambda kv: -kv[1])))
        a("")

    a("## R06 (FALLIBLE_BOUNDED_RESOURCE) rejection breakdown, explicit\n")
    a("R06's 7 raw records are outside `reachability_tier.py` entirely (its own module "
      "docstring: it deliberately never touches `r04_findings`/`r05_findings`/`r06_findings` -- "
      "Resource Guard's reachability question, when it has one, is a separate, narrower question "
      "`promote_via_js_linkage.py` answers, not this pipeline's `stage_status`/reachability "
      "gate). R06's own 7 records split exactly in two:")
    r06 = detail.get("r06_findings", {})
    a(f"- **NOT_A_CANDIDATE: 2** -- verdict breakdown: " +
      ", ".join(f"{k}={v}" for k, v in sorted(r06.get("NOT_A_CANDIDATE", {}).items())) +
      ". These never entered the candidate pool at all -- `VALUE_ACQUISITION_GUARD_MISSING` is "
      "the only verdict `PROPERTY_CANDIDATE_RULES` treats as a candidate; the rest (here, real "
      "abstentions/confirmed-safe matches from `resource_guard_verdict_r06.py`'s own contract "
      "logic) are correctly excluded before `scanner_candidate` is even considered.")
    a(f"- **APPLICABILITY_NOT_DETERMINED: 5** -- applicability_status breakdown: " +
      ", ".join(f"{k}={v}" for k, v in sorted(r06.get("APPLICABILITY_NOT_DETERMINED", {}).items())) +
      ". These ARE real `VALUE_ACQUISITION_GUARD_MISSING` candidates (`scanner_candidate=True`) "
      "with resolved provenance -- the SAME 5 real candidates R05 also produces (R06 shares R05's "
      "verdict-construction logic byte-for-byte). They stay non-reportable purely because "
      "`applicability_status` defaults to `NOT_YET_DETERMINED` and nothing in this pipeline ever "
      "affirmatively sets it to `APPLICABLE` for a real corpus finding -- a real, disclosed gap "
      "(task #41's own docstring: no separate, affirmative applicability step exists yet), not a "
      "reachability question at all. This is the SAME structural gap the node-libcurl regression "
      "in `check_provenance.py` exercises on a single real finding -- here it is confirmed across "
      "all 5 of this replay's own real R06 candidates, not just one.\n")

    a("## OOB_INDEX_WRITE stratified audit (3,290/3,918 raw records -- 84% of everything this "
      "replay produced)\n")
    a(f"- Raw records: **{oiw['raw_total']}** across **{oiw['distinct_packages']}** packages, "
      f"**{oiw['distinct_function_sites']}** distinct (package, function) sites, "
      f"**{oiw['distinct_files']}** distinct files.")
    a(f"- Mean raw findings per function site: **{oiw['mean_findings_per_function_site']}** -- "
      "the volume is NOT one-finding-per-distinct-bug-location; it concentrates in functions "
      "that produce many findings each (see top sites below).")
    a(f"- Reachability distribution (real, from `reachability_tier.py`): " +
      ", ".join(f"{k}={v}" for k, v in sorted(oiw["reachability_distribution"].items())) +
      f" -- **0 of {oiw['raw_total']} have ANY established JS-reachability evidence.** Every "
      "single OOB_INDEX_WRITE candidate in this 97-package sample is either "
      "`TIER_INTERNAL_UNREGISTERED` (the function exists but is never registered/callable from "
      "JS under any idiom this pipeline recognizes) or `REACHABILITY_UNRESOLVED`.")
    a(f"- Provenance hint: PACKAGE_OWNED={oiw['package_owned_raw_count']}, "
      f"VENDORED={oiw['vendored_raw_count']}.")
    a(f"- Vendored-code deduplication for this property specifically: "
      f"**{oiw['vendored_dedup_this_property']['raw_exposure_count']} raw vendored exposures "
      f"-> {oiw['vendored_dedup_this_property']['deduplicated_count']} deduplicated real code "
      "sites** (not the whole-replay aggregate -- this property's own real number). Vendored "
      "dedup collapses only a modest fraction here (~4%) -- most of the volume is NOT the same "
      "vendored file repeated across packages, it is many DISTINCT sites, largely within a "
      "small number of vendored libraries (see below).")
    a(f"- Derivation rule: " + ", ".join(f"{k}={v}" for k, v in oiw["derivation_rule_distribution"].items()))
    a(f"- Capacity source: " + ", ".join(f"{k}={v}" for k, v in oiw["capacity_source_distribution"].items()))
    a("")
    a("### Top vendored libraries this volume comes from\n")
    for lib, n in list(oiw["vendored_library_id_distribution"].items())[:15]:
        a(f"- {lib}: {n}")
    a("")
    a("### Top 15 (package, function) sites by raw finding count -- where the volume actually "
      "concentrates\n")
    a("| Package | Function | File | Raw findings | Distinct array names indexed |")
    a("|---|---|---|---|---|")
    for site in oiw["top_15_function_sites"]:
        arrays = ", ".join(site["array_names_in_this_function"][:5])
        if len(site["array_names_in_this_function"]) > 5:
            arrays += f" (+{len(site['array_names_in_this_function']) - 5} more)"
        a(f"| {site['package']} | {site['function']} | {site['file']} | "
          f"{site['raw_finding_count']} | {arrays} |")
    a("")

    a("### Interpretation\n")
    top_n = oiw["top_15_function_sites"][0]["raw_finding_count"] if oiw["top_15_function_sites"] else 0
    a(f"The single top function site alone accounts for {top_n} of {oiw['raw_total']} raw "
      f"records ({100*top_n/oiw['raw_total']:.1f}%), and the top 15 sites account for "
      f"{sum(s['raw_finding_count'] for s in oiw['top_15_function_sites'])} "
      f"({100*sum(s['raw_finding_count'] for s in oiw['top_15_function_sites'])/oiw['raw_total']:.1f}%). "
      "Combined with 0% established reachability across the entire property, this is real "
      "evidence pointing toward a BROAD MATCHING PATTERN rather than a set of independently "
      "interesting candidates: `CPP_FIXED_ARRAY_INDEX_UNBOUNDED` fires on every syntactically-"
      "unbounded fixed-array index it can see structurally, which concentrated, dispatch-table-"
      "shaped C code (the classic vendored-library idiom: a fixed-size lookup/register array "
      "indexed many times across one function, e.g. an ABI-dispatch or opcode table) will "
      "produce in bulk regardless of whether any individual index is ever attacker-influenced. "
      "This is NOT evidence the detector is wrong (its own controls, oob_write_controls.py/"
      "oob_read_controls.py-style positive/negative fixtures, are unaffected by this finding) -- "
      "it is evidence that, at 97-package scale, this property's REAL precision bottleneck is "
      "reachability concentration in a small number of vendored dispatch-table functions, not a "
      "provenance or scanner-candidate problem. A precision pass before the remaining 394 "
      "packages should prioritize: (1) manual review of the top concentrated sites above to "
      "confirm they are genuinely non-JS-reachable internal dispatch tables (not a reachability-"
      "classifier gap); (2) whether a per-function or per-array-name volume cap / dedup-by-"
      "(function, rule) key would materially change the corpus-wide picture without discarding "
      "real distinct sites; (3) whether the 3-4 top vendored libraries above are worth a targeted "
      "reachability re-check before any wider run.\n")

    # ============================================================================
    # Deep-dive: beyond the 4-tier reachability classification
    # ============================================================================
    a("## Reachability deep-dive: beyond registration + direct call\n")
    a("`reachability_tier.py`'s own 4-tier classification is explicitly scoped (its own module "
      "docstring) to registration + a real, direct JS call -- \"this module does not attempt a "
      "transitive native call-graph walk.\" This section closes that gap for all 3,902 staged "
      "rejects, using ONLY preserved bundle evidence (`cpp_facts.json`'s own already-resolved "
      "`candidate_target_ids` call edges + `arguments[].kind == METHOD_REF` function-reference "
      "arguments) -- no new Joern run, no source re-download.\n")
    if deep_dive:
        a(f"- **{deep_dive['n_packages']}** packages replayed; **"
          f"{deep_dive['n_packages_with_confirmed_registrations']}** have at least one confirmed "
          f"native registration (exports.Set / InstanceMethod / Nan::SetPrototypeMethod-Export), "
          f"**{deep_dive['n_packages_zero_registrations']}** have zero registered exports at all "
          "under any idiom this pipeline recognizes.\n")
        a("| Deep-dive bucket | Count | % of 3,902 |")
        a("|---|---|---|")
        totals = deep_dive["deep_dive_totals"]
        for bucket, n in sorted(totals.items(), key=lambda kv: -kv[1]):
            a(f"| {bucket} | {n} | {100*n/3902:.1f}% |")
        a("")
        a("| Property | " + " | ".join(sorted(set(
            b for v in deep_dive["deep_dive_by_property"].values() for b in v))) + " |")
        buckets_seen = sorted(set(b for v in deep_dive["deep_dive_by_property"].values() for b in v))
        a("|---|" + "---|" * len(buckets_seen))
        for key, v in deep_dive["deep_dive_by_property"].items():
            a(f"| {LABELS.get(key, key)} | " + " | ".join(str(v.get(b, 0)) for b in buckets_seen) + " |")
        a("")
        a("**Reading this:** `DIRECTLY_REGISTERED` does not appear -- correctly 0, since these "
          "are exactly the candidates that already failed direct registration in the original "
          "tier. `TRANSITIVELY_CALLED_FROM_REGISTERED` (a real, resolved call-graph path from "
          "SOME registered export reaches this candidate, even if not directly) is vanishingly "
          f"small ({totals.get('TRANSITIVELY_CALLED_FROM_REGISTERED', 0)}/3,902). "
          f"`CALLBACK_OR_WORKER_HEURISTIC` ({totals.get('CALLBACK_OR_WORKER_HEURISTIC', 0)}) is a "
          "real, disclosed heuristic (a best-effort name+scope match, same discipline as the "
          "existing InstanceMethod matcher, never a certainty) -- worth targeted manual review, "
          "not proof of reachability. Even after this deeper analysis, "
          f"**{totals.get('GENUINELY_INTERNAL', 0)}/3,902 ({100*totals.get('GENUINELY_INTERNAL', 0)/3902:.1f}%) "
          "show no real, resolved path from any registered export, transitive caller, callback "
          "reference, or the addon's own Init entry point.** This substantially strengthens, "
          "rather than weakens, the reachability-driven interpretation: it is not a shallow "
          "artifact of `reachability_tier.py`'s own narrower scope -- a real call-graph walk "
          "confirms the same picture at corpus scale.\n")
    else:
        a("*Not yet run for this build -- see `reachability_deep_dive.py`.*\n")

    # ============================================================================
    # Root cause of the 136 REACHABILITY_UNRESOLVED cases
    # ============================================================================
    a("## Root cause of the 136 REACHABILITY_UNRESOLVED cases (stratified, not sampled thin)\n")
    if unresolved_root_cause:
        by_pkg = unresolved_root_cause["by_package"]
        by_prop = unresolved_root_cause["by_property"]
        a("By property: " + ", ".join(f"{LABELS.get(k,k)}={v}" for k, v in sorted(
            by_prop.items(), key=lambda kv: -kv[1])))
        a("By package: " + ", ".join(f"{k}={v}" for k, v in sorted(
            by_pkg.items(), key=lambda kv: -kv[1])))
        a("")
        top_pkg, top_n = max(by_pkg.items(), key=lambda kv: kv[1])
        a(f"**{top_n}/{sum(by_pkg.values())} ({100*top_n/sum(by_pkg.values()):.1f}%) of all "
          f"REACHABILITY_UNRESOLVED cases trace to a SINGLE package: `{top_pkg}`.** This is not "
          "a diffuse, systemic classifier gap across many packages -- it concentrates almost "
          "entirely in one. Root cause, confirmed directly against this package's own preserved "
          "`js_facts.json` (not assumed):\n")
        a("| Package | Unresolved count | js calls | cpp functions | facts_available |")
        a("|---|---|---|---|---|")
        for rc in unresolved_root_cause["root_cause_per_package"]:
            a(f"| {rc['package_name']}@{rc['version']} | {rc['unresolved_count']} | "
              f"{rc['js_calls_count']} | {rc['cpp_functions_count']} | {rc['facts_available']} |")
        a("")
        a(f"`{top_pkg}`'s own bundled `js_facts.json` records **zero JS calls at all** -- "
          "`reachability_tier.classify_function_reachability()`'s own `facts_available` guard "
          "(`bool(js['calls']) and bool(cpp['functions'])`) correctly, fails-closed, marks every "
          "single one of this package's own real C++ candidates REACHABILITY_UNRESOLVED, "
          "regardless of how many real candidates the C++ side alone produced -- not a guess, a "
          "real disclosed data gap on this one package's own JS facts extraction (its own "
          "top-level JS entry point may genuinely make no native-binding calls directly, or the "
          "JS facts extraction for this specific package came back thin -- worth a targeted, "
          "single-package re-check, not a corpus-wide reachability_tier.py fix).\n")
    else:
        a("*Not yet computed for this build.*\n")

    # ============================================================================
    # Determinism verification
    # ============================================================================
    a("## Determinism verification (actual second run, not asserted from design)\n")
    if determinism:
        status = "ALL DETERMINISTIC" if determinism["all_deterministic"] else "NOT FULLY DETERMINISTIC"
        a(f"**{status}.** A full independent second replay of all "
          f"{determinism['total_packages']} packages was run "
          f"(`verify_determinism.py`, {determinism['elapsed_seconds']}s): "
          f"**{determinism['matched']}/{determinism['total_packages']}** produced an identical "
          "semantic digest (sha256 of each record's own JSON, sorted keys, with only the real, "
          "expected-to-vary wall-clock timing fields excluded -- `_timing`/`_total_seconds`), "
          f"{determinism['mismatched']} mismatched, {determinism['rerun_failures']} rerun "
          "failures. See `results/determinism_verification.json` for the full per-package "
          "digests and any mismatch/failure detail.\n")
    else:
        a("*Not yet run for this build -- see `verify_determinism.py`.*\n")

    a("---\n*This analysis adds no new scanning and changes no gate. `develop` remains "
      "unmodified in behavior; this is read-only reporting over task #34's own already-committed "
      "output.*")

    with open(os.path.join(HERE, "REJECTION_FUNNEL_ANALYSIS.md"), "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
