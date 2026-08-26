#!/usr/bin/env python3
"""
provenance_scan.py — one-command wrapper over the portable provenance pipeline.

Replaces the manual sequence used all session:
    scan_repo.py -> frontend facts -> EndToEndRunner (SINKS=...) -> hand triage.

It does NOT change engine semantics. It runs the frozen engine, queries a sink
list, and emits the sink-by-source provenance table (EXACT / MAY / UNRESOLVED,
proven origins, abstentions) as text or JSON. Feature freeze is untouched.

Usage:
    provenance_scan.py TARGET --lang {c,js,auto} --sinks name:idx,name:idx
                       [--summary-lib FILE] [--json OUT] [--work DIR]

Exit status is always 0 on a completed scan; a nonzero status means the pipeline
itself failed (frontend/engine error), never "a sink looked dangerous".
"""
import argparse, json, os, re, subprocess, sys, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCAN_REPO = ROOT / "tools" / "scan_repo.py"
ENGINE_BUILD = ROOT / "tests" / "gates" / "jsts-r05" / "build"

# Per-language sidecar argv for EndToEndRunner. The engine loads args[0] as the
# primary doc and the rest as extras; order is not significant to the loader but
# every produced sidecar must be passed.
SIDECARS = {
    "js": lambda w: [w/"js.json", w/"js_state.json", w/"js_identity.json",
                     w/"js_capture.json", w/"js.json.expression.json",
                     w/"js.json.source.json"],
    "c":  lambda w: [w/"p.json", w/"p.json.memory.json", w/"p.json.expression.json",
                     w/"p.json.reachingdef.json", w/"p.json.source.json"],
}
PRIMARY = {"js": "js.json", "c": "p.json"}


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def detect_lang(target):
    p = pathlib.Path(target)
    files = list(p.rglob("*")) if p.is_dir() else [p]
    exts = {f.suffix for f in files}
    if {".c", ".cpp", ".cc", ".h", ".hpp"} & exts:
        return "c"
    return "js"


def frontend(target, lang, work):
    """Run scan_repo.py to produce neutral fact JSON. Returns the work dir."""
    out = work / "scan.json"
    r = run([sys.executable, SCAN_REPO, target, "--lang", lang,
             "--work", work, "--out", out],
            env={**os.environ})
    if not (work / PRIMARY[lang]).exists():
        sys.stderr.write("FRONTEND FAILED:\n" + r.stderr[-2000:] + "\n")
        raise SystemExit(2)
    return work


def engine(lang, work, sinks):
    """Invoke the frozen engine with the sink query. Returns parsed SINK rows."""
    args = SIDECARS[lang](work)
    # NOTE: the curated summary file is NOT passed to the engine. The strict
    # loader correctly REFUSES unknown schemas (fail-loud), so summaries are held
    # by the scanner and applied as annotation only (see annotate_summaries).
    env = {**os.environ, "SINKS": sinks}
    r = run(["java", "-cp", str(ENGINE_BUILD), "EndToEndRunner", *args], env=env)
    rows = []
    for line in r.stdout.splitlines():
        m = re.match(r"SINK (\S+) (\S+)#(\d+) resolution=(\S+) proven=\[([^\]]*)\]"
                     r" may=\[([^\]]*)\] unknown=(\S+) origins=\[([^\]]*)\]"
                     r" mayOrigins=\[([^\]]*)\]", line)
        if m:
            rows.append({
                "function": m.group(1), "sink": m.group(2), "arg": int(m.group(3)),
                "resolution": m.group(4),
                "proven": [int(x) for x in m.group(5).split(",") if x.strip()],
                "may": [int(x) for x in m.group(6).split(",") if x.strip()],
                "unknown": m.group(7) == "true",
                "origins": [x.strip() for x in m.group(8).split(",") if x.strip()],
                "may_origins": [x.strip() for x in m.group(9).split(",") if x.strip()],
            })
    if not rows and "Exception" in r.stdout + r.stderr:
        sys.stderr.write("ENGINE ERROR:\n" + (r.stdout + r.stderr)[-2000:] + "\n")
        raise SystemExit(3)
    return rows


def load_summaries(path):
    if not path:
        return {}
    d = json.load(open(path))
    return {e["name"]: e["returns"] for e in d.get("summaries", [])}


def annotate_summaries(rows, work, lang, sums):
    """Presentation-only: for ABSTAINED rows whose sink argument is a call to a
    known library function, note the curated return class. Does NOT change any
    resolution — the engine's abstention stands; this only tells the human WHY
    the boundary is external and what class the value would carry IF the curated
    summary layer were consumed (a separate, gated milestone)."""
    if not sums:
        return
    try:
        primary = json.load(open(work / PRIMARY[lang]))
    except Exception:
        return
    calls = {c.get("id"): c for c in primary.get("calls", [])}
    by_fn = {}
    for c in primary.get("calls", []):
        by_fn.setdefault(c.get("enclosing_function_id"), []).append(c)
    for r in rows:
        if r["bucket"] != "ABSTAINED":
            continue
        # does this function call any summarised library function?
        fid = next((f["id"] for f in primary.get("functions", [])
                    if f.get("name") == r["function"]), None)
        hits = {c["name"] for c in by_fn.get(fid, []) if c.get("name") in sums}
        if hits:
            r["summary_hint"] = sorted((n, sums[n]) for n in hits)


def classify(row):
    """Map an engine row to a triage bucket. Provenance semantics unchanged;
    this is presentation only."""
    res = row["resolution"]
    if res == "EXACT" and (row["proven"] or row["origins"]):
        return "PROVEN_ORIGIN"          # value derives from a named parameter
    if res == "EXACT":
        return "PROVEN_SOURCE_FREE"     # positively no parameter origin
    if res in ("AMBIGUOUS", "POSSIBLE_UNBOUNDED") and (
            row["may"] or row["may_origins"] or row["unknown"]):
        return "MAY_ORIGIN"             # possible lineage, uncertainty preserved
    if res == "HEURISTIC":
        return "DISPATCH_ONLY"
    return "ABSTAINED"                  # UNRESOLVED


def render_text(rows, target, lang):
    buckets = {}
    for r in rows:
        buckets.setdefault(classify(r), []).append(r)
    print(f"# provenance scan: {target}  (lang={lang})")
    print(f"# {len(rows)} sink instances queried\n")
    order = ["PROVEN_ORIGIN", "MAY_ORIGIN", "PROVEN_SOURCE_FREE",
             "DISPATCH_ONLY", "ABSTAINED"]
    for b in order:
        rs = buckets.get(b, [])
        if not rs:
            continue
        print(f"## {b}  ({len(rs)})")
        for r in rs:
            org = (f" proven={r['proven']}" if r["proven"]
                   else (f" may={r['may']}" if r["may"] else ""))
            if r["origins"]:
                org += f" origins={r['origins']}"
            if r["may_origins"]:
                org += f" may_origins={r['may_origins']}"
            unk = " unknown" if r["unknown"] else ""
            hint = ""
            if r.get("summary_hint"):
                hint = "  <- external: " + ", ".join(f"{n}={c}" for n, c in r["summary_hint"])
            print(f"  {r['function']:24s} {r['sink']}#{r['arg']:<2d} "
                  f"{r['resolution']}{org}{unk}{hint}")
        print()
    print("# counts: " + ", ".join(f"{b}={len(buckets.get(b, []))}" for b in order))
    print("# NOTE: provenance evidence only. A PROVEN/MAY origin is not a")
    print("#       vulnerability; adjudication is a separate manual step.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--lang", default="auto", choices=["auto", "c", "js"])
    ap.add_argument("--sinks", required=True,
                    help="comma list of name:argIndex, e.g. exec:0,memcpy:2")
    ap.add_argument("--summary-lib", default=None,
                    help="optional curated external-library summary JSON (D-layer)")
    ap.add_argument("--json", default=None, help="write machine-readable rows here")
    ap.add_argument("--work", default=None)
    a = ap.parse_args()

    lang = detect_lang(a.target) if a.lang == "auto" else a.lang
    work = pathlib.Path(a.work) if a.work else pathlib.Path(tempfile.mkdtemp())
    work.mkdir(parents=True, exist_ok=True)

    frontend(a.target, lang, work)
    rows = engine(lang, work, a.sinks)
    for r in rows:
        r["bucket"] = classify(r)
    sums = load_summaries(a.summary_lib)
    annotate_summaries(rows, work, lang, sums)

    if a.json:
        json.dump({"target": a.target, "lang": lang, "sinks": a.sinks,
                   "rows": [{**r, "bucket": classify(r)} for r in rows]},
                  open(a.json, "w"), indent=1)
    render_text(rows, a.target, lang)
    return 0


if __name__ == "__main__":
    sys.exit(main())
