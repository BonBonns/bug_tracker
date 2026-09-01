#!/usr/bin/env python3
"""Build facts for the 10 frozen token-bearing packages and run the frozen R02
analyzer exactly once per package. Hash-verifies each pinned tarball; scoped parse
(exclude vendored deps/prebuilds) on OOM, disclosed per package. Emits one JSON per
package plus a combined roll-up. No source is read for classification -- only the
frozen analyzer over real Joern facts."""
import csv, hashlib, io, json, os, subprocess, sys, tarfile, urllib.request

SV = os.path.dirname(os.path.abspath(__file__))
STUDY = f"{SV}/study/napi_status"
OUT = f"{STUDY}/validation_10"
# Classpath to the pinned Joern v4.0.608 (Maven Central assembly -- see
# check_napi_status.py for the recipe; the release zip is unreachable here). Override
# with NAPI_JOERN_CP if assembled elsewhere.
CP = os.environ.get("NAPI_JOERN_CP") or open(
    os.environ.get("NAPI_JOERN_CP_FILE", os.path.expanduser("~/joern-mvn/cp.txt"))
).read().strip()
EXPORT = os.path.normpath(f"{SV}/../../tchecker-research-complete/portable-engine-full-"
                          "review-package/tests/gates/cpp-r06/frontend/"
                          "export_c_cpp_facts_v03.sc")
WORK = os.environ.get("NAPI_VAL_WORKDIR", os.path.join(
    __import__("tempfile").gettempdir(), "napi_val10"))
os.makedirs(OUT, exist_ok=True)
os.makedirs(WORK, exist_ok=True)

frozen = json.load(open(f"{STUDY}/VALIDATION_10_FROZEN.json"))
sample = {(r["package_name"], r["version"]): r
          for r in csv.DictReader(open(f"{SV}/npm_corpus/overnight_100/"
                                        "overnight_sample_100.tsv"), delimiter="\t")}


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def java(args, heap, extra=None):
    base = ["java", f"-Xmx{heap}", "-Djava.util.concurrent.ForkJoinPool."
            "common.parallelism=2", "-cp", CP] + (extra or [])
    return sh(base + args, cwd=WORK)


def build_facts(name, ver):
    row = sample[(name, ver)]
    safe = name.replace("/", "__")
    wdir = f"{WORK}/{safe}"
    os.makedirs(wdir, exist_ok=True)
    data = urllib.request.urlopen(row["tarball_url"], timeout=300).read()
    if hashlib.sha256(data).hexdigest() != row["tarball_sha256"]:
        return None, "TARBALL_HASH_MISMATCH", None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(f"{wdir}/pkg", filter="data")
    open(f"{WORK}/.installation_root", "w").close()
    cpg = f"{wdir}/pkg.cpg.bin"
    facts = f"{OUT}/raw_{safe}"
    # try full parse, then scoped on failure
    r = java(["io.joern.c2cpg.Main", "-o", cpg, f"{wdir}/pkg"], "6g")
    scope = "full"
    if not os.path.exists(cpg):
        r = java(["io.joern.c2cpg.Main", "-o", cpg, f"{wdir}/pkg",
                  "--exclude", "package/deps", "--exclude", "package/prebuilds",
                  "--exclude", "package/build", "--exclude", "package/node_modules"],
                 "12g")
        scope = "scoped_excl_deps_prebuilds_build_node_modules"
    if not os.path.exists(cpg):
        return None, "CPG_GENERATION_FAILED", r.stderr[-400:]
    r = java(["io.joern.joerncli.console.ReplBridge", "--script", EXPORT,
              "--param", f"cpgFile={cpg}", "--param", f"outDir={facts}"], "6g")
    if not os.path.isfile(f"{facts}/methods.tsv"):
        return None, "FACT_EXPORT_FAILED", r.stderr[-400:]
    os.remove(cpg)
    return facts, scope, None


roll = []
for p in frozen["packages"]:
    name, ver = p["name"], p["version"]
    print(f"=== {name}@{ver}", flush=True)
    try:
        facts, scope, err = build_facts(name, ver)
    except Exception as e:
        facts, scope, err = None, f"EXCEPTION:{type(e).__name__}", str(e)[:300]
    if facts is None:
        rec = {"package": name, "version": ver, "outcome": "INFRASTRUCTURE_FAILURE",
               "reason": scope, "detail": err}
        print("  INFRA_FAIL:", scope, flush=True)
    else:
        safe = name.replace("/", "__")
        outp = f"{OUT}/out_{safe}.json"
        sub = sh([sys.executable, f"{SV}/napi_status_verdict_r02.py", facts, outp])
        res = json.load(open(outp))
        rec = {"package": name, "version": ver, "outcome": "ANALYZED",
               "parse_scope": scope, "classification": res["classification"],
               "proven_wrappers": res.get("proven_propagating_wrappers", []),
               "findings": res["findings"]}
        print("  ANALYZED:", res["classification"], flush=True)
    json.dump(rec, open(f"{OUT}/summary_{name.replace('/', '__')}.json", "w"),
              indent=1, sort_keys=True)
    roll.append(rec)

json.dump(roll, open(f"{OUT}/rollup.json", "w"), indent=1, sort_keys=True)
print("\n=== DONE ===")
for r in roll:
    if r["outcome"] == "ANALYZED":
        print(f"{r['package']:48} {r['classification']}")
    else:
        print(f"{r['package']:48} INFRA_FAIL: {r['reason']}")
