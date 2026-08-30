# RESOURCE-GUARD-R05 design: structured-evidence recovery for unresolved static factories

## What R05 is not

R05 does NOT change R01-R04's own matching path. Every call whose `methodFullName` already
resolves and matches a `REAL_CONTRACTS`/`SYNTHETIC_CONTRACTS` entry the way R04 already
handles it is handled EXACTLY as R04 would -- byte-for-byte, same code. R05 adds exactly one
NEW path, taken only when R04's own qualifier check would otherwise abstain
(`ACQUISITION_SIGNATURE_UNRECOGNIZED`) AND the call's own `methodFullName` is the specific,
structurally-recognizable "totally unresolved" shape (`<unresolvedNamespace>.<name>:
<unresolvedSignature>(N)`) c2cpg emits for these calls -- confirmed real, not assumed, via
`AB_FIXTURE_RESULT.md` and direct Joern-REPL inspection of two real corpus packages.

## The evidence chain -- no code-string matching as the basis for any gate

Every step below reads a real, already-exported, structural CPG field. `code` (the literal
source text) is carried into findings for human disclosure only, exactly as R01-R04 already
do -- it is never read by any gate.

1. **Call name** (`calls.tsv` `name` column, decoded, not `methodFullName`): must equal a
   `RECOVERY_CONTRACTS` entry's `acquisition_call` (e.g. `"New"`).
2. **Dispatch type** (`calls.tsv` `dispatchType` column -- exported by
   `export_c_cpp_facts_v03.sc` already, just not previously read by R01-R04's Python side):
   must be `STATIC_DISPATCH`. Real, structural evidence this is a class-qualified call, not
   an unrelated free function or instance method of the same name.
3. **The unresolved shape itself**: `methodFullName` must start with
   `<unresolvedNamespace>.` and contain `:<unresolvedSignature>(` -- this is what
   distinguishes "c2cpg saw a qualified static call it could not bind" from a call that
   resolved to some OTHER, real, non-matching qualifier (e.g. a genuinely different real
   class) or an entirely unrelated unresolved call. A call that resolves to a CONCRETE but
   non-matching qualifier is correctly left to R04's own existing rejection path, never
   routed through recovery -- recovery is strictly narrower than "didn't match", it targets
   only this one specific, confirmed frontend shape.
4. **Result-object identity + declared-type evidence** (`arguments.tsv`'s own
   `type_full_name` column for the assignment's LHS `IDENTIFIER` argument -- already
   exported, unchanged from what R01-R04 already read for their own object-identity/alias
   resolution): same technique R01-R04 already use to find the enclosing
   `<operator>.assignment` (same-line, then code-substring fallback -- unchanged), but the
   LHS identifier's own `type` field is now the PRIMARY identity evidence, checked against a
   `RECOVERY_CONTRACTS` entry's `result_type_forms` (plural -- see the disclosed
   inconsistency below) instead of R04's single `result_type` string.
5. **Exact argument arity** (`len(args_by_call[cid])`, the REAL count of exported argument
   nodes -- NOT `_param_count(mfn)`, which is meaningless for an unresolved signature: the
   trailing `(N)` in `<unresolvedSignature>(N)` is c2cpg's own raw ARGUMENT COUNT marker, not
   a parenthesized param list, so R04's existing `_param_count` helper would silently
   misparse it as a single param named `"N"` -- confirmed by reading the string directly, not
   assumed. R05 computes arity independently and never reuses `_param_count` for a recovered
   call.). Must equal the contract's `required_arity` (2, for `Napi::Buffer::New`'s
   allocating overload) -- the external-data 3-arg overload and the templated 4-arg finalizer
   overload both correctly fall through unrecovered by this same exact-arity check, with no
   separate exclusion list needed.
6. **Argument role** (`arguments.tsv` `type_full_name` for argument index 1 -- the first real
   parameter under this project's established indexing convention, index 0 being the absent
   receiver for a `STATIC_DISPATCH` call): must be in the contract's `arg0_env_type_forms`
   (`"Napi.Env"`/`"Env"` -- both real forms have been observed for other, resolved `Napi::`
   calls in the same real files, per the header-staging fix's own confirmed resolution of
   `env` arguments).
7. **Applicable contract**: only after all six gates above pass does R05 synthesize a
   concrete, single-site contract (`result_type` set to whichever real form THIS site
   actually showed) and hand it, unchanged, to R04's own existing object-identity/alias-
   resolution/failure-predicate/dominance-walk/attacker-trace machinery -- reused as-is, not
   reimplemented, since that machinery already operates generically over any
   `result_type`-shaped contract dict.

## Disclosed nuance: result-type form inconsistency (real, not assumed)

`AB_FIXTURE_RESULT.md` records two real, independently-observed forms for the SAME real
class across real corpus code: bare `"Buffer"` and namespace-qualified `"Napi.Buffer"`.
`RECOVERY_CONTRACTS["Napi::Buffer"]["result_type_forms"] = ("Buffer", "Napi.Buffer")` accepts
either. This is a real, disclosed widening relative to R03's own single-string
`qualifier_type`/`result_type` fields -- necessary because R05 is recovering evidence the
FRONTEND itself represents inconsistently, not because R05's own matching is looser than
R01-R04's. The exact-prefix, no-substring-matching discipline R03 established is preserved
here as exact SET membership (not a prefix, not a substring) against these two, and only
these two, real, independently-confirmed forms -- never widened further on guesswork.

## Verdict/classification additions

New classification keys, all appended alongside R04's existing ones, none replacing them:
`R05_RECOVERY_CANDIDATE` (gate 1-3 passed), `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED` (gate 4
failed -- includes the case where the local's own type ALSO failed to resolve, e.g. `"ANY"`
or an `auto`-deduced ambiguous form: this correctly ABSTAINS rather than guessing),
`R05_RECOVERY_ARITY_UNRECOGNIZED` (gate 5 failed), `R05_RECOVERY_ARG_ROLE_UNRECOGNIZED` (gate
6 failed), `R05_ACQUISITION_CALL_RECOVERED` (all six gates passed -- the recovered-evidence
equivalent of R04's `ACQUISITION_CALL_FOUND`). From there, verdicts are the SAME set R04
already reports (`VALUE_ACQUISITION_GUARD_MISSING`/`..._ESTABLISHED`,
`CONTRACT_NOT_APPLICABLE`, `BUILD_CONFIGURATION_UNRESOLVED`/`_CONFLICT`,
`VALUE_ACQUISITION_SEMANTICS_UNRESOLVED`), with an added `"evidence_source": "r05_structural_
recovery"` field on every recovered finding so a reader can always tell a recovered finding
apart from a directly-resolved R04 one -- never silently merged into the same-looking output.

## Scope boundaries, stated up front, not discovered later

- Only `Napi::Buffer::New`'s 2-arg allocating overload is curated in `RECOVERY_CONTRACTS` for
  this pass -- matching R02/R03/R04's own existing `REAL_CONTRACTS` scope exactly (New only,
  not Copy/NewOrCopy). The SAME mechanism could extend to `Napi::ArrayBuffer`,
  `Napi::External<T>`, `Napi::Buffer::Copy` in future work; not attempted here, to avoid
  scope creep beyond what this pass proves out.
- Only the "call result assigned to an explicitly-typed local via `<operator>.assignment`"
  pattern is covered -- a direct `return Napi::Buffer<T>::New(...)` with no intermediate
  local, or a call passed directly as another call's argument, is NOT covered by this pass
  and falls through unrecovered (abstains, does not guess). Real corpus usage (Cartesi,
  sqlite3) predominantly uses the covered pattern; this boundary is stated here so it is not
  discovered as a surprise later.
- The underlying c2cpg resolution trigger itself remains unexplained (see
  `AB_FIXTURE_RESULT.md`) -- R05 recovers from the OBSERVED, CONFIRMED behavior, not from a
  root-caused mechanism.
