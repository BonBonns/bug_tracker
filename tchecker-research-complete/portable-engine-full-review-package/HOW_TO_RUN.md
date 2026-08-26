# Portable Provenance Engine — how to run

Baseline: 7ad2880e04e84fd5 (engine-core; verified by snapshot-equality). Canonical suite: 31/31, REGRESSIONS 0.

## Prerequisites
- Java (JDK 17+) for the engine core.
- Python 3.10+ for the frontends, scanner, and verdict tools.
- Joern (c2cpg.sh for C/C++, jssrc2cpg.sh for JS/TS) installed; set JOERN_HOME.

## Layout
- core/provenance-neutral/  : the Java engine (PortableProvenanceEngine, OriginRef, ...)
- core/provenance/          : the SEPARATE class-aware PHP engine (PHPCGFactory)
- core/program_graph/       : the strict ProgramGraphLoader + fact records
- frontends/ , tests/gates/cpp-r06/frontend/ : Joern export + neutral-fact normalizers
- scanner/provenance_scan.py : one-command repo scan -> triage buckets
- tools/                    : standalone readers incl. oob_write_verdict.py / oob_read_verdict.py
- tests/run_all.py          : the canonical gate suite (needs JOERN_HOME etc.)
- review-deliverable docs are in the SEPARATE findings zip.

## Run the canonical suite
    export JOERN_HOME=/path/to/joern-cli
    export JOERN=$JOERN_HOME/joern JSSRC2CPG=$JOERN_HOME/jssrc2cpg.sh
    export REPLAY_DIR=$PWD/tests/replay-corpus
    python3 tests/run_all.py
Expect: EXECUTED 31/31, REGRESSIONS 0, GUARD-R01 PASS.

## Scan a C/C++ repo through the memory-safety chain
    $JOERN_HOME/c2cpg.sh -o /tmp/cpg.bin /path/to/repo
    $JOERN_HOME/joern --script tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc \
        --param cpgFile=/tmp/cpg.bin --param outDir=/tmp/raw
    python3 tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py /tmp/raw /tmp/p.json
    python3 tools/oob_write_verdict.py /tmp/p.json     # CANDIDATE OOB_WRITE sites
    python3 tools/oob_read_verdict.py  /tmp/p.json     # CANDIDATE OOB_READ sites

Verdicts are labelled CANDIDATE, never VULNERABLE. The engine abstains where its
neutral facts are insufficient (e.g. pool/allocation or external capacity).
