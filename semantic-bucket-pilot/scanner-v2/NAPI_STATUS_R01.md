# NAPI-STATUS-R01: raw N-API return-code / output-initialization handling

A **software-reliability property**, not a vulnerability detector. For each supported
fallible N-API creation call, the capability determines from real Joern-derived graph
facts whether execution can reach a use of the call's output parameters without first
establishing `napi_ok`. Every verdict is an API-handling classification with node-id
evidence. **Claims boundary:** no record produced by this capability is a
vulnerability, severity, exploitability, or impact claim, and none may be quoted as
one; the capability also never characterizes what an unestablished output would do at
runtime.

## Supported calls (this revision)

| call | arity | size role | output roles |
|---|---|---|---|
| `napi_create_buffer` | 4 | arg 2 | arg 3 (`void** data`), arg 4 (`napi_value* result`) |
| `napi_create_buffer_copy` | 5 | arg 2 | arg 4 (`void** result_data`), arg 5 (`napi_value* result`) |

`napi_create_external_buffer` is **deliberately unregistered** in this revision: its
memory-ownership and lifetime semantics differ (caller-owned external data, finalizer
contract), so its correct-handling shapes are not this property's shapes. The c09
control proves exclusion is by registration, not by luck.

## Program shape recognized

1. a supported creation call, identified by callee name + `STATIC_DISPATCH` + exact
   registered arity (`calls.tsv`);
2. its `napi_status` result identified by **node identity** (the call node's one
   structural consumer: assignment RHS / comparison operand / return child / call
   argument / provably absent);
3. its output pointer and output JavaScript value identified by **argument role**
   (registered indices), each resolved through `<operator>.addressOf` to an
   identifier's `refsTo` referent, or a plain forwarded pointer identifier;
4. a CFG-reachable output use (any identifier referencing an output referent outside
   the call's own argument subtree) without a proven-success status on every incoming
   path;
5. the input-size argument's origin recorded **for diagnostics only** (literal /
   parameter / assignment-traced); it carries no intent or impact meaning and no
   verdict depends on it.

## Correct handling recognized (no finding)

- `status != napi_ok` guarding a terminating failure path before any output use (c02);
- `status == napi_ok` success branch containing every output use (c07);
- returning the status (or the creation call itself) before any output use (c06/c06b);
- a same-fact-base wrapper proven to **propagate** (identity filter, c10) or
  **terminate on failure** (registered terminating call on every failure path, p03);
- provable compound conditions only: through `logicalAnd` for success-on-true, through
  `logicalOr` for success-on-false (p04).

## Required abstentions (neither flagged nor cleared)

- ambiguous call identity (arity/dispatch mismatch) — `ABSTAIN_CALL_IDENTITY_UNRESOLVED` (p07);
- ambiguous status-result identity (unmodeled operator consumer) — `ABSTAIN_STATUS_IDENTITY_UNRESOLVED`;
- ambiguous output identity (out-arg not a resolvable variable, e.g. `&slots[i]`) —
  `ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED` (c08);
- wrapper behavior unavailable/unresolved (external or unproven callee consuming the
  status) — `ABSTAIN_WRAPPER_UNRESOLVED` (c11);
- branch polarity/dominance not established (unprovable compounds, unresolved branch
  shapes, exhausted walk budgets) — `ABSTAIN_BRANCH_POLARITY_UNRESOLVED` (p05).

## Pinned-exporter conventions (verified, not assumed)

Two structural conventions of the pinned toolchain (Joern v4.0.608 +
`export_c_cpp_facts_v03.sc`) are load-bearing and re-verified by `check_napi_status.py`
on every run against the frozen facts:

1. a condition node's **first** cfg successor is its TRUE target (the same convention
   `resource_guard_verdict_r04.resolve_branch_targets` already relies on) — p01 probes;
2. the CFG emits **no** edges into `METHOD_RETURN`: return nodes and noreturn calls
   (`abort`) are terminal, and a void method's final fall-through edge is omitted —
   the encoding `prove_terminating_guard` is written against.

## Files

- `napi_status_verdict.py` — the analyzer (standalone; NOT wired into
  `six_property_aggregator.py`, whose six-property contract stays frozen; provenance/
  reachability/applicability/adjudication modules untouched — interfaces preserved by
  addition only).
- `check_napi_status.py` — regression gate: the 11 required controls + probes, 32
  checks, over frozen real facts in `study/napi_status/raw_synthetic/`.
- `study/napi_status/fixture_source.c` — control fixture (compiled, not imagined).

## Real-package protocol (pre-registered BEFORE any package result was read)

The overnight-diagnostic-100 evidence bundles are not present in this checkout (they
are gitignored scratch outputs), so package facts are regenerated with the SAME pinned
toolchain: fetch the frozen sample's pinned tarball → verify `tarball_sha256` against
`overnight_100/overnight_sample_100.tsv` → extract C/C++ sources → c2cpg v4.0.608 →
`export_c_cpp_facts_v03.sc` → `napi_status_verdict.py`.

- **Candidate triage:** iterate the frozen sample in its own row order; a package is a
  candidate iff its verified sources contain the token `napi_create_buffer` (text
  triage decides only WHICH packages to analyze, never any verdict — verdicts come
  from graph facts alone).
- **Development package:** the FIRST candidate in frozen order. Its result may be used
  to fix representation bugs (fixes must keep every control green).
- **Freeze:** sha256 of `napi_status_verdict.py` recorded below before blind selection.
- **Blind package:** the NEXT candidate in frozen order after the development package,
  selected only after the freeze, analyzed exactly once, reported as-is.

Results are recorded in `study/napi_status/REAL_PACKAGE_RESULTS.md`.
