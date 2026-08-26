# Gate 24-TS status

## Built
- 8 TypeScript conformance fixtures.
- Real-CPG exporter for METHOD, METHOD_PARAMETER_IN, METHOD_RETURN, TYPE_DECL, MEMBER, LOCAL, CALL, arguments, and IDENTIFIER/REF facts.
- Neutral JSON normalizer.
- Characterization checker that records actual callee sets instead of guessing Joern's union/interface/generic behavior.
- Fail-closed runner that requires real `jssrc2cpg` and `joern`.

## Locally verified
- Python scripts compile.
- Shell runners pass `bash -n`.
- Cumulative historical/fixture regression remains 14/14 executed with 0 regressions; Gates 2-9 are recorded historical artifacts.

## Not verified
The real Joern TypeScript frontend was not executed in this environment because `jssrc2cpg` and `joern` are not installed. Local runner result: exit 20, `REAL_JOERN_TS_BLOCKED: jssrc2cpg not found`.

## Promotion rule
Do not call Gate 24-TS PASS until a real Joern run produces `typescript_facts.json`, all hard CPG/type-preservation checks pass, and the dispatch observations are reviewed. Union/interface/generic outcomes are intentionally empirical rather than preregistered guesses.
