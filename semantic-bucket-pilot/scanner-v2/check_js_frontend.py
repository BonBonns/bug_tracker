#!/usr/bin/env python3
"""JS-frontend validation: proves the pinned JS toolchain (astgen 3.47.0 built from
joernio/astgen-monorepo + jssrc2cpg 4.0.608) produces correct, non-empty JS facts on a
MINIMAL known fixture BEFORE it is trusted on real packages (node-libcurl in
check_provenance.py, leveldb-zlib in the full pipeline).

Toolchain resolution is machine-local and never hard-coded here: the jssrc2cpg
launcher and its ASTGEN_BIN come from $JOERN_HOME (default: the gitignored
tchecker-research-complete/joern-install/joern-cli, where the machine-local shims
live) or the Maven classpath in $NAPI_JOERN_CP / $NAPI_JOERN_CP_FILE plus $ASTGEN_BIN.
If no toolchain is resolvable this SKIPS (exit 0 with a clear notice) rather than
failing -- the toolchain is environment setup, not repository content. See
TOOLCHAIN_MAVEN_ASSEMBLY.md and ASTGEN_PIN.json.

Every check is JS-fact mechanics; nothing here is a security claim."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "study", "napi_status", "js_frontend_fixture", "minimal.js")
JS_FRONTEND = os.path.normpath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete", "portable-engine-full-review-package",
    "frontends", "javascript-typescript", "joern"))
JOERN_HOME = os.environ.get("JOERN_HOME", os.path.normpath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete", "joern-install", "joern-cli")))


def _resolve():
    """Returns a callable (js_cpg_out_path, src_dir) -> None that runs jssrc2cpg, or
    None if no machine-local toolchain is available."""
    sh = os.path.join(JOERN_HOME, "jssrc2cpg.sh")
    if os.path.isfile(sh):
        return lambda out, src: subprocess.run([sh, "-o", out, src],
                                                capture_output=True, text=True, timeout=300)
    cp = os.environ.get("NAPI_JOERN_CP")
    if not cp:
        for f in ([os.environ["NAPI_JOERN_CP_FILE"]] if os.environ.get("NAPI_JOERN_CP_FILE")
                  else []) + [os.path.expanduser("~/joern-mvn/cp.txt")]:
            if os.path.isfile(f):
                cp = open(f).read().strip()
                break
    astgen = os.environ.get("ASTGEN_BIN")
    if cp and astgen and os.path.isfile(astgen):
        env = dict(os.environ, ASTGEN_BIN=astgen)
        return lambda out, src: subprocess.run(
            ["java", "-Xmx4g", "-cp", cp, "io.joern.jssrc2cpg.Main", "-o", out, src],
            capture_output=True, text=True, timeout=300, env=env)
    return None


def main():
    runner = _resolve()
    if runner is None:
        print("SKIP: no machine-local JS toolchain resolvable (JOERN_HOME shim or "
              "NAPI_JOERN_CP+ASTGEN_BIN). Set it up per TOOLCHAIN_MAVEN_ASSEMBLY.md.")
        print("JS_FRONTEND_VALIDATION=SKIPPED")
        return 0

    ok = total = 0

    def ck(name, cond):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(("PASS" if cond else "FAIL"), name)

    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        with open(FIXTURE) as f:
            open(os.path.join(src, "minimal.js"), "w").write(f.read())
        js_bin = os.path.join(td, "js.cpg.bin")
        runner(js_bin, src)
        ck("jssrc2cpg produced a non-empty JS CPG from the minimal fixture "
           "(astgen parsed the JS)", os.path.isfile(js_bin) and os.path.getsize(js_bin) > 0)
        if not (os.path.isfile(js_bin) and os.path.getsize(js_bin) > 0):
            print(f"JS_FRONTEND_VALIDATION={ok}/{total}")
            return 1

        raw = os.path.join(td, "js_raw")
        open(os.path.join(JOERN_HOME, ".installation_root"), "a").close() \
            if os.path.isdir(JOERN_HOME) else None
        joern = os.path.join(JOERN_HOME, "joern")
        export = os.path.join(JS_FRONTEND, "export_neutral.sc")
        if os.path.isfile(joern):
            subprocess.run([joern, "--script", export, "--param", f"cpgFile={js_bin}",
                            "--param", f"outDir={raw}"], capture_output=True, text=True,
                           timeout=300)
        else:
            cp = os.environ.get("NAPI_JOERN_CP") or open(
                os.environ.get("NAPI_JOERN_CP_FILE",
                               os.path.expanduser("~/joern-mvn/cp.txt"))).read().strip()
            marker_dir = os.path.join(td, "root")
            os.makedirs(marker_dir)
            open(os.path.join(marker_dir, ".installation_root"), "w").close()
            subprocess.run(["java", "-Xmx4g", "-cp", cp,
                            "io.joern.joerncli.console.ReplBridge", "--script", export,
                            "--param", f"cpgFile={js_bin}", "--param", f"outDir={raw}"],
                           capture_output=True, text=True, timeout=300, cwd=marker_dir)
        norm = os.path.join(td, "js_facts.json")
        subprocess.run([sys.executable, os.path.join(JS_FRONTEND, "normalize_joern_facts.py"),
                        raw, norm], capture_output=True, text=True, timeout=120)
        ck("export_neutral + normalize produced a JS facts doc", os.path.isfile(norm))
        facts = json.load(open(norm)) if os.path.isfile(norm) else {}
        names = {f.get("name") for f in facts.get("functions", [])}
        ck("the fixture's runIterator function appears in the normalized JS facts",
           "runIterator" in names)
        call_names = {c.get("callee_name") or c.get("name") for c in facts.get("calls", [])}
        ck("a real call is captured in the JS facts (non-empty calls list)",
           len(facts.get("calls", [])) > 0)

    print(f"JS_FRONTEND_VALIDATION={ok}/{total}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
