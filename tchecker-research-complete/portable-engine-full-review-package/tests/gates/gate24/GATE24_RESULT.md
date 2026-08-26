# Gate 24 — Real Joern JavaScript/TypeScript frontend

## Purpose

Replace the temporary TypeScript→PHP-shaped CSV layer at the *first layer* with
Joern's real `jssrc2cpg` frontend. The output is normalized to a language-neutral
program-fact contract before the portable core sees it.

## Target pipeline

```text
JS / TS source
   ↓
Joern jssrc2cpg          (real language frontend)
   ↓
Joern CPG                (METHOD/CALL/PARAM/IDENTIFIER/etc.)
   ↓
export_neutral.sc
   ↓
normalize_joern_facts.py
   ↓
portable-program-facts/0.1
   ↓
portable core
```

There is no PHP AST emulation in this path.

## Gate fixture

```ts
export function helper(value: string): string { return value; }
export function main(input: string): string { return helper(input); }
```

## Pass criteria

The real CPG must demonstrate `helper` and `main`, their formal parameters, a
`helper(input)` CALL inside `main`, exactly one demonstrated callee equal to the
`helper` METHOD, and argument identity for `input`. The normalized call must therefore
be `EXACT`. No security source/sink concepts are part of this gate.

## Verification status in this package build

**RUN and PASSED against a real Joern install.** Joern CLI (joern-cli, bundled
`codepropertygraph-domain-classes 1.7.70`) was downloaded from the official
`joernio/joern` GitHub releases and installed locally. `run_gate24.sh` was executed
with `JSSRC2CPG`/`JOERN` pointed at the real `jssrc2cpg.sh` / `joern` executables
(no PATH shortcuts, no prototype adapter substitution) and exited 0 with:

```text
GATE24=10/10
```

Verified 2026-08-20. All ten checks (method existence, formal parameters, the
`helper(input)` call inside `main`, single demonstrated callee, `EXACT` resolution,
argument identity, and absence of any security-layer concept) passed against the
real CPG, not the `ts2legacycsv.js` prototype oracle.

### Note on a prior stale artifact

This package previously shipped a `run/` directory containing a `program_facts.json`
and `result.txt` that already claimed `GATE24=10/10`, while `local_attempt.err` /
`local_attempt.exitcode` (exit 20) recorded `REAL_JOERN_BLOCKED`. Those two artifacts
contradicted each other and should not have been trusted as-is. The fresh run
performed here regenerated `run/joern/program_facts.json` and `run/result.txt` from
scratch with a real `jssrc2cpg` invocation, and the regenerated facts match the
previously-shipped ones. Treat any future gate artifact that lacks a reproducible,
freshly-executed command trail with the same suspicion until it's been re-run.
