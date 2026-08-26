#!/usr/bin/env bash
# verify_tchecker.sh -- exercise Component A end to end. Missing fixture = FAILURE, never SKIP.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="$ROOT/tchecker-property-adjudicator"
FAIL=0
WORK="$(mktemp -d)"

echo "=== 1. adjudicator regression tests (no Joern needed) ==="
( cd "$TC/adjudicator" && python3 test_abstention_collapse.py 2>&1 | tail -1 )
( cd "$TC/adjudicator" && python3 test_abstention_collapse.py 2>&1 | grep -q "ALL PASS" ) \
  && echo "OK    test_abstention_collapse" || { echo "FAIL  test_abstention_collapse"; FAIL=1; }
( cd "$TC/adjudicator" && python3 test_source_coverage.py 2>&1 | grep -q "ALL PASS" ) \
  && echo "OK    test_source_coverage" || { echo "FAIL  test_source_coverage (fixture missing counts as FAIL)"; FAIL=1; }

echo ""
echo "=== 2. full evidence packet: FxA customs.js (LLM adjudication boundary) ==="
( cd "$TC/adjudicator" && \
  TCH_RAW="$ROOT/examples/A_full_evidence_fxa_customs/cand1-ps/raw" \
  TCH_SRC="$ROOT/examples/A_full_evidence_fxa_customs/corpus-scan" \
  TCH_OUT="$WORK/fxa_out" TCH_SINK=30064771145 \
  TCH_FINDING="fxa/packages/fxa-auth-server/lib/customs.js" \
  TCH_HINTS=no_hints.json python3 adjudicate_js.py > "$WORK/fxa.log" 2>&1 )
grep -E "FINAL|rounds" "$WORK/fxa.log" || true

# required: reached the LLM boundary at all -- BOTH artifacts must exist (audit + compact packet)
[ -f "$WORK/fxa_out/llm_input_1.json" ] \
  && echo "OK    llm_input_1.json generated (reached LLM adjudication boundary)" \
  || { echo "FAIL  no llm_input_1.json produced"; FAIL=1; }
[ -f "$WORK/fxa_out/audit_evidence_1.json" ] \
  && echo "OK    audit_evidence_1.json generated (full evidence retained separately)" \
  || { echo "FAIL  no audit_evidence_1.json produced"; FAIL=1; }

# required: expected disposition
grep -q "CANDIDATE_OPEN" "$WORK/fxa.log" \
  && echo "OK    disposition CANDIDATE_OPEN as expected" \
  || { echo "FAIL  unexpected disposition"; FAIL=1; }

# required: every unresolved transform sent to the LLM has its required code inline when
# body_supplied=true -- checked on the COMPACT packet's own step, not the audit array.
python3 - "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
subj = d["unresolved_subject"]
step = next(s for s in d["alternative"]["steps"] if s["node_id"] == subj["call_node_id"])
body_supplied = step["definition_status"] in ("ESTABLISHED", "ESTABLISHED_BY_TRACE")
ok = (not body_supplied) or bool(step.get("definition_body"))
print("OK    unresolved transform's step carries definition_body when body_supplied=true" if ok
      else "FAIL  body_supplied=true but definition_body missing on the step")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: no LLM packet requires PATH_CODE_CONTEXT lookup
python3 - "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
ok = "PATH_CODE_CONTEXT" not in d
print("OK    LLM packet has no PATH_CODE_CONTEXT (nothing to cross-reference)" if ok
      else "FAIL  LLM packet still contains PATH_CODE_CONTEXT")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: no LLM packet requires RELEVANT_CODE lookup for the property subject
python3 - "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
ok = "RELEVANT_CODE" not in d and "RELEVANT_CODE" not in d["QUESTION"]
print("OK    LLM packet has no RELEVANT_CODE and QUESTION does not reference it" if ok
      else "FAIL  LLM packet or its QUESTION still references RELEVANT_CODE")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: audit and LLM packet agree on node IDs/property IDs
python3 - "$WORK/fxa_out/audit_evidence_1.json" "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
audit=json.load(open(sys.argv[1])); packet=json.load(open(sys.argv[2]))
ok = (audit["finding_id"] == packet["finding_id"]
      and audit["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["property_id"] == packet["property_id"]
      and audit["STILL_NOT_DETERMINISTICALLY_ESTABLISHED"]["subject"]["call_node_id"]
          == packet["unresolved_subject"]["call_node_id"])
print("OK    audit_evidence and llm_input agree on finding_id/property_id/call_node_id" if ok
      else "FAIL  audit and LLM packet disagree on identity fields")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: UNKNOWN remains UNKNOWN until an accepted SAFE/UNSAFE hint resolves it -- exercised
# directly here (not just by the standalone regression tests) using the real customs.js finding.
python3 - "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
ok = d["unresolved_subject"]["deterministic_status"] == "UNKNOWN"
print("OK    unresolved_subject.deterministic_status is UNKNOWN pre-hint, as required" if ok
      else "FAIL  deterministic_status was not UNKNOWN before any hint was supplied")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: PATH_CODE_CONTEXT non-empty in the AUDIT artifact specifically (real bodies, not nulls)
python3 - "$WORK/fxa_out/audit_evidence_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
pcc=d.get("PATH_CODE_CONTEXT") or []
ok = bool(pcc) and any(
    (s.get("definition_body") or s.get("callsite_code"))
    for e in pcc for s in (e.get("steps") or [])
)
print("OK    audit_evidence PATH_CODE_CONTEXT populated with real code" if ok else "FAIL  PATH_CODE_CONTEXT empty/null")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: PATH_FLOW_CONTEXT non-empty for this known example (audit artifact only --
# the compact LLM packet deliberately does not carry this section)
python3 - "$WORK/fxa_out/audit_evidence_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
pfc=d.get("PATH_FLOW_CONTEXT") or []
ok = any((e.get("transitions") or []) for e in pfc)
print("OK    audit_evidence PATH_FLOW_CONTEXT populated with real transitions" if ok else "FAIL  PATH_FLOW_CONTEXT empty")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

# required: the sanitizePayload semantic question, in the actual LLM-facing packet
grep -q "sanitizePayload" "$WORK/fxa_out/llm_input_1.json" \
  && echo "OK    sanitizePayload semantic question present in the LLM packet" \
  || { echo "FAIL  sanitizePayload question missing"; FAIL=1; }

# required: alternative.sink carries its own code inline too (source and steps already did;
# sink was the last remaining outside-lookup gap for a genuinely self-contained packet)
python3 - "$WORK/fxa_out/llm_input_1.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
snk = d["alternative"]["sink"]
ok = bool(snk.get("expression")) and bool(snk.get("containing_statement")) and bool(snk.get("containing_function"))
print("OK    alternative.sink carries expression/containing_statement/containing_function inline" if ok
      else "FAIL  alternative.sink missing inline code context")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && FAIL=1

echo ""
echo "=== 3. deterministic property case (NoSQL, resolves without LLM) ==="
if [ -z "${JOERN_HOME:-}" ]; then
  echo "FAIL  JOERN_HOME unset -- required for the deterministic Joern-backed case"
  FAIL=1
else
  "$JOERN_HOME/jssrc2cpg.sh" "$TC/fixtures/nosqli_prop_effects" -o "$WORK/nosqli.cpg.bin" >/dev/null 2>&1
  mkdir -p "$WORK/nosqli_raw"
  "$JOERN_HOME/joern" --script "$TC/producers/export_nosqli_integ.sc" \
      --param cpgFile="$WORK/nosqli.cpg.bin" --param rawDir="$WORK/nosqli_raw" \
      --param srcLabel=VERIFY --param skipCount=0 > "$WORK/nosqli.log" 2>&1
  grep -q "PRESERVES targets (not type-guarded): 4 of 9" "$WORK/nosqli.log" \
    && echo "OK    NoSQL Stage2/3: 4 of 9 PRESERVES as expected" \
    || { echo "FAIL  NoSQL producer result changed"; FAIL=1; }
  SINK=$(head -1 "$WORK/nosqli_raw/source_facts.tsv" | cut -f1)
  ( cd "$TC/adjudicator" && TCH_RAW="$WORK/nosqli_raw" TCH_SRC="$TC/fixtures/nosqli_prop_effects" \
    TCH_OUT="$WORK/nosqli_out" TCH_SINK="$SINK" TCH_FINDING=verify-nosqli \
    TCH_HINTS=no_hints.json TCH_PROPERTY_CONFIG="$TC/property_configs/nosqli_query_op.json" \
    TCH_SINK_KIND=findOne python3 adjudicate_js.py > "$WORK/nosqli_adj.log" 2>&1 )
  grep -q "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS" "$WORK/nosqli_adj.log" \
    && echo "OK    NoSQL resolved deterministically (0 LLM rounds)" \
    || { echo "FAIL  NoSQL did not resolve deterministically"; FAIL=1; }
fi

echo ""
if [ $FAIL -eq 0 ]; then echo "VERIFY_TCHECKER=PASS"; else echo "VERIFY_TCHECKER=FAIL"; fi
rm -rf "$WORK"
exit $FAIL
