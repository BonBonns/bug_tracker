#!/usr/bin/env python3
"""Thin subprocess wrapper around one oob_*_verdict.py module's emit_candidates(), so its
real memory use can be isolated the same way as every other scanner in the large-bundle
test (resource.getrusage(RUSAGE_CHILDREN) around a subprocess, matching run_pipeline_one.py's
own rss_now() technique) -- the in-process import used elsewhere in this pilot is fine for
timing but cannot isolate its own RSS delta from the parent harness's.

Run: python3 oob_runner.py <modname> <cpp_facts.json> <out.json>
"""
import importlib.util
import json
import sys

OOB_TOOLS = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tools"


def main():
    modname, cpp_facts, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    spec = importlib.util.spec_from_file_location(modname, f"{OOB_TOOLS}/{modname}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    candidates = mod.emit_candidates(cpp_facts)
    with open(out_path, "w") as f:
        json.dump({"candidates": candidates}, f)
    print(f"{modname}: {len(candidates)} candidates")


if __name__ == "__main__":
    main()
