# Joern frontend provenance (Step 2 unblock)

The frozen scanner consumes `portable-program-facts/0.3` fact files produced by
joern-c2cpg. To scan new disclosed CVEs, joern-c2cpg 4.0.608 was installed in
this session and verified functional.

## Pinned binary

- Tool: joern-cli (contains c2cpg), pinned tag **v4.0.608**
- Asset: `joern-cli-linux-x86_64.zip`
- Source URL: `https://github.com/joernio/joern/releases/download/v4.0.608/joern-cli-linux-x86_64.zip`
- Size: 1821051748 bytes
- SHA256: `97989843f7d6be1449296936644b04803e80723e607648c33edf87ded6202ded`
- Installed at: `/tmp/joern-cli` (JOERN_HOME); JVM: OpenJDK 21
- Verified: produced a CPG from a trivial C file (exit 0), and c2cpg.sh runs.

Fact-file metadata records frontend version `4.0.608`, matching the cached
corpus, so new scans use the SAME frontend as the frozen corpus.

## Fact-generation command (per input)

From the C source checkout, reproducing `portable-program-facts/0.3`:

```sh
JOERN_HOME=/tmp/joern-cli
"$JOERN_HOME/c2cpg.sh" -o cpg.bin <SRC_DIR>
"$JOERN_HOME/joern" --script \
   tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc \
   --param cpgFile=cpg.bin --param outDir=raw
python3 \
   tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py \
   raw program.json     # program.json == the cpp.json the frozen producers read
```

## Source fetch (verified reachable over the proxy)

- `git ls-remote https://github.com/mozilla/nss.git` -> OK
- raw.githubusercontent.com fetch of an NSS file -> HTTP 200

So new disclosed-CVE source can be fetched and scanned here. The scanner and
bucket schema stay frozen (v1); only new fact INPUTS are added.

## Pipeline reproduction validated

Re-scanned an EXISTING cached CVE checkout (cve-2016-1950/vuln) with this Joern
install and ran the frozen producers on the regenerated facts. Result: IDENTICAL
to the cached corpus — same status counts (abstained 4) and the same single
llm-eligible candidate (`sec_asn1d_add_to_subitems/copy` →
`unknown_allocator_contract`). So newly-generated facts are frozen-compatible;
scanning new CVEs with this toolchain is sound.
