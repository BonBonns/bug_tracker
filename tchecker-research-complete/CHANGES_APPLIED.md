# Changes applied to this bundle (r02)

Four fixes, each root-caused and verified on real code, no gate regressions.

1. fail-open detector — R02+R03  (tchecker-property-adjudicator/producers/export_fail_open_candidates.sc)
   - R02: exclude discarded terminal continuations (`.then(next, next)`).
   - R03: security signal relocated from the enclosing method to the CONSUMER of the defaulted
     value (does the .then result reach a security decision, interprocedurally).
   - On real fxa-customs-server: 5 FP / 1 FN  ->  0 FP / 0 FN (records.js:20 now caught).
   - Frozen gate gate_fail_open_security_control.py still 8/8.

2. C/C++ frontend — origin-preserving cast pass-through
   (portable-engine-full-review-package/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py)
   - `<operator>.cast [TYPE_REF, value]` resolves through to the value operand.
   - Real Firefox netwerk/base/nsURLHelper.cpp: proven 4 -> 11; OPERATOR abstentions 10 -> 5.
   - Gates: cpp-r06 10/10, cpp-param-r01 12/12, CORE-EXPRESSION/MEMORY/REACHINGDEF PASS.
   - WITHDRAWN: a field-read pass-through (obj.field -> base param origin) was attempted and
     REVERTED as UNSOUND. Controls proved it over-taints when a parameter field is written
     before being read: over_const (a.x=5;return a.x) wrongly claimed param 0; over_param
     (a.x=y;return a.x) wrongly claimed param 0 instead of param 1. A sound version needs
     flow-sensitive write-tracking (promote to base-param origin only with no intervening
     write on the path). Left abstaining rather than guessing.

3. polyglot linker — recognize the `bindings` native-loader idiom
   (portable-engine-full-review-package/tests/gates/poly-r01/merge_polyglot.py)
   - Accept `bindings:` tags alongside `node-gyp-build:` / `.node:`.
   - node-addon-examples 2_function_arguments: JS->C++ edges 0 -> 1 (add->Add, EXACT).
   - poly-r01 (bcrypt) still 10/10.

4. packaging — restored the executable bit on all */*.sh (the original zip dropped it, which
   made run_gate24*.sh fail with "Permission denied").

## Known-blocked (not a tool gap)
Real Gecko-scale C++ coverage needs a mach build's compile_commands.json to resolve macros/
includes; verified the lever (scan_repo --preprocess) clears macro abstentions when includes are
present. Requires a Firefox checkout+build, which was unavailable in the build sandbox.

5. NEW CAPABILITY — OOB-INDEX-R01 (evidence-gated by MOZ-OOB-R01 Row 3)
   tools/oob_index_write_verdict.py ; tests/gates/oob-index-r01/ (gate + frozen fixtures + README)
   - Detects OOB writes via indexed stores into fixed-size arrays arr[idx] (incl. arr[idx].field);
     element count read syntactically so OPAQUE element types (e.g. WEBAUTHN_EXTENSION) are handled.
   - Standalone producer; the frozen analyzer + its 20+ gates are UNCHANGED.
   - Gate OOB_INDEX_R01=6/6: Row 3 CVE-2022-28281 VULN->CANDIDATE / FIXED->suppressed; safe controls
     (const, direct idx<K bound, sizeof guard) suppressed; Rows 1 & 2 no false positives.
   - Emits CANDIDATE only. Honest limits documented in the gate README (recall traded for precision;
     intraprocedural heuristic guard analysis). Does NOT address Row 1 (pointer-param runtime capacity)
     or Row 2 (cross-TU capacity).

6. NEW CAPABILITY — OOB-ADJ-R01 (wire OOB candidates into the adjudicator/LLM pipeline)
   adjudicator/adjudicate_oob.py ; property_configs/oob_index_write.json ;
   tests/gates/oob-adj-r01/ (self-contained gate + frozen fixtures)
   - Stages OOB (index-store) CANDIDATEs into the SAME tchecker-llm-packet/1.0 schema + the
     SAFE|UNSAFE|UNKNOWN advisory-hint contract used by the JS classes and the fail-open class.
   - DISCIPLINE: never upgrades to VULNERABLE (asserted per-packet); candidate_class preserved,
     deterministic_status stays UNKNOWN; the LLM answer is an advisory HINT, not a verdict.
   - Gate OOB_ADJ_R01=10/10: Row 3 VULN stages exactly 1 well-formed packet (class OOB_WRITE,
     no 'VULNERABLE', question names array/index/capacity); FIXED stages 0; a HIGH-confidence SAFE
     hint resolves the candidate (RESOLVED_SAFE_BY_ACCEPTED_HINT, no packet).
   - Frozen analyzer + its 20+ gates UNCHANGED.

7. OOB pipeline wired into the CANONICAL entry point (scan_repo.py) + trusted-hint rule
   tools/scan_repo.py: after the c/c++ facts are normalized, scan_repo now automatically runs the
   OOB index-store producer + adjudicator and emits review packets to <work>/oob_review/ (reported
   as side['oob_review']). New optional flag --oob-hints (trusted attestation file).
   Verified end-to-end from CLEAN dirs via the public command (no manual scripts / no file moving):
     VULN dir  -> oob_review.packets == 1 (packet: OOB_WRITE / UNKNOWN / no 'VULNERABLE')
     PATCHED dir -> oob_review.packets == 0
   TRUSTED-HINT RULE (adjudicate_oob.disposition + property_configs/oob_index_write.json):
     a SAFE hint suppresses a candidate ONLY from a trusted source (CURATED_ATTESTATION/HUMAN_REVIEW)
     at HIGH confidence. A model-generated (source LLM) or unsourced SAFE is ADVISORY ONLY and does
     NOT erase the deterministic candidate. Gate OOB_ADJ_R01=14/14 covers this.

8. OOB-ADJ-R02 — trust from the INGESTION CHANNEL, not a caller-controlled field
   A hint's self-declared "source" is NEVER consulted for trust. load_channels() assigns trust by
   which flag/path loaded the hint: --oob-trusted-attestations => trusted (may suppress);
   --oob-hints => untrusted advisory (source claims stripped & overwritten to UNTRUSTED_CHANNEL).
   Controls (hermetic gate OOB_ADJ_R01=12/12 + canonical via scan_repo):
     - a model/untrusted hint FALSELY declaring source=CURATED_ATTESTATION stays advisory (packet emitted)
     - only the trusted curated-attestation channel suppresses
     - reusing an output dir leaves NO stale packet after scanning patched code
     - OOB producer/adjudicator failure => NONZERO scan exit (never a silent packets=0)
   Analyzer frozen; 20+ gates UNCHANGED.

9. OOB-ADJ-R03 — trusted attestations are bound to a canonical evidence fingerprint
   property_id = "oob-index:{fingerprint}.index_within_capacity"; fingerprint = sha256 over
   {analyzer_version, repo_rev, file, candidate_class, subclass, array, elem_count, index_expr, line}.
   scan_repo now computes repo_rev (git) and forwards it; it also clears a prior report at scan start
   so a FAILED rescan cannot leave a stale-current report. Producer fault clears packets before it
   can raise. Gates: OOB_ADJ_R03=15/15 (every field re-fingerprints; changed repo/file invalidate;
   ambiguous duplicates never suppress; declared-fact mismatch rejected; fault-after-success raises &
   leaves no stale packet). Canonical C1-C4 verified via scan_repo. Analyzer frozen.

10. OOB-ADJ-R04 — trusted-identity / content-binding (identity derived by runtime, not caller labels)
    - repo_rev (commit id) REMOVED from the trust anchor (kept only as informational metadata). The
      fingerprint now binds content_sha256 = full SHA-256 of the ACTUAL scanned bytes (working tree;
      covers uncommitted/untracked/dirty edits), computed by scan_repo._scanned_content_map from the
      exact bytes fed to the frontend. Unverified content -> FAIL CLOSED (never suppress).
    - analyzer_identity = full SHA-256 over component files (producer + adjudicator + config + frontend
      normalizer + exporter). No manual version string.
    - FULL 64-hex sha-256 for the trust decision; explicit canonical JSON (fixed names/types).
    - Fingerprint additionally binds function identity + source span.
    - No caller-controlled flag/field selects analyzer/content/repo identity; identity keys inside a
      hint are stripped. Suppression recomputes the fingerprint from producer facts + trusted digests;
      a fingerprint echoed in a packet/hint is never trusted.
    Gate OOB_ADJ_R04=20/20; canonical C1-C3 via scan_repo (incl. dirty-worktree with identical
    candidate fields). Analyzer frozen.
