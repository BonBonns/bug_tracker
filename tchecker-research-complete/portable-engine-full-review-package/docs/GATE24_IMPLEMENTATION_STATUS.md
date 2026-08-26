# Gate 24 implementation status

## Built

- Real `jssrc2cpg` invocation wrapper.
- Joern non-interactive CPG exporter (`export_neutral.sc`).
- Neutral fact normalizer (`portable-program-facts/0.1`).
- Direct-function TypeScript fixture.
- Gate checker that requires a demonstrated `main -> helper` call target and classifies it EXACT.
- Cumulative regression runner reports Gate 24 separately from legacy regressions.

## Locally verified

- Python components compile.
- Runner fails closed when Joern is absent (`REAL_JOERN_BLOCKED`, exit 20/21).
- Existing executable Gates 10-23 remain 14/14 PASS after adding the new frontend layer.
- Historical Gates 2-9 remain present as recorded artifacts.

## Not verified here

A real `jssrc2cpg` CPG was not generated in this environment because the Joern
executables are not installed and shell network access cannot fetch the official
release. Therefore Gate 24 is `BLOCKED`, not `PASS`.

## Pass condition

On a machine with Joern installed:

```bash
cd tests/gates/gate24
JSSRC2CPG=/path/to/jssrc2cpg JOERN=/path/to/joern ./run_gate24.sh
```

Promotion requires `GATE24=N/N` with zero failures from a real Joern-produced CPG.
