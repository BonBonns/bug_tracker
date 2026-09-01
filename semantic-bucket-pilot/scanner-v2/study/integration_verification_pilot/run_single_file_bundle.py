#!/usr/bin/env python3
"""Builds a real evidence bundle (cpp_raw/ + cpp_facts.json + sidecars) from ONE standalone
C/C++ source file, through the exact same real c2cpg -> export_c_cpp_facts_v03.sc ->
normalize_c_cpp_facts_v03.py chain the npm pipeline uses -- for real historical-case source
files (wolfSSL / Mozilla Tremor fixtures already committed in-repo), not npm tarballs.

Run: python3 run_single_file_bundle.py <source_file.c> <work_dir>
"""
import os
import subprocess
import sys
import time

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"


def main():
    src = sys.argv[1]
    work = sys.argv[2]
    os.makedirs(work, exist_ok=True)
    cpp_bin = os.path.join(work, "cpp.cpg.bin")

    t0 = time.time()
    r = subprocess.run([f"{JOERN_HOME}/c2cpg.sh", "-o", cpp_bin,
                         "--define", "NAPI_DISABLE_CPP_EXCEPTIONS", src],
                        capture_output=True, text=True, timeout=180)
    print(f"c2cpg rc={r.returncode} {time.time()-t0:.2f}s", file=sys.stderr)
    if r.returncode != 0:
        print(r.stdout[-3000:], file=sys.stderr)
        print(r.stderr[-3000:], file=sys.stderr)
        sys.exit(1)

    cpp_raw = os.path.join(work, "cpp_raw")
    t0 = time.time()
    r = subprocess.run([f"{JOERN_HOME}/joern", "--script",
                         f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc",
                         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"],
                        capture_output=True, text=True, timeout=180)
    print(f"export rc={r.returncode} {time.time()-t0:.2f}s", file=sys.stderr)
    if r.returncode != 0:
        print(r.stdout[-3000:], file=sys.stderr)
        sys.exit(1)

    cpp_facts = os.path.join(work, "cpp_facts.json")
    t0 = time.time()
    r = subprocess.run([sys.executable, f"{CPP_FRONTEND}/normalize_c_cpp_facts_v03.py",
                         cpp_raw, cpp_facts], capture_output=True, text=True, timeout=180)
    print(f"normalize rc={r.returncode} {time.time()-t0:.2f}s", file=sys.stderr)
    if r.returncode != 0:
        print(r.stderr[-3000:], file=sys.stderr)
        sys.exit(1)

    print(f"BUNDLE_READY cpp_raw={cpp_raw} cpp_facts={cpp_facts}")


if __name__ == "__main__":
    main()
