# RESOURCE-GUARD-R01: FALLIBLE_BOUNDED_RESOURCE, a new capability distinct from every
# existing property in this project

Built in response to a real, confirmed coverage gap: the destination-capacity-write scanner
(`oob_runtime_capacity_v2.py`) was measured against `CVE-2020-1896` (Facebook Hermes,
`hermesBuiltinApply`, CWE-787) and found zero write operations at all — not "judged safe,"
never even considered a candidate (see `study/js_c_transition/README.md`'s measurement
section). The real bug: `ScopedNativeCallFrame` allocates `len` register slots on a bounded
runtime stack, where `len` is a JS array's `.length` (fully attacker-controlled); if that
allocation would overflow, the constructor sets an internal flag and returns *without* a
usable frame, and `hermesBuiltinApply` writes into it anyway because it never calls the
object's own `overflowed()` predicate. This is a real write-capacity bug, but not a shape
the write-property scanner's four capabilities model (fixed stack array, memcpy-family
wrapper, pointer-walk write, external decoder contract) — a fifth, genuinely different
representation.

## The general property

```
FALLIBLE_BOUNDED_RESOURCE
    acquisition/constructor receives attacker-influenced size
    + acquisition may produce an invalid/overflowed state
    + resource is subsequently used
    + no dominating guard proves validity before that use
```

Deliberately **not** implemented as "any RAII object with an `isValid()`/`overflowed()`-
shaped method" — that heuristic has two real false-positive modes, both covered by
synthetic controls below: (a) a class whose constructor genuinely cannot fail (no size
parameter at all) — calling an unrelated bool-returning method on it proves nothing; (b) an
uncontracted class that happens to define a same-named method — matching by name alone,
ignoring the receiver's resolved type, would treat unrelated code as this pattern.

## The curated-contract mechanism (`resource_contracts.py`)

The only way `resource_guard_verdict.py` learns a class is a fallible bounded resource: a
data table, one entry per class, each field citation-backed against a real header at a
real revision — never inferred from a class's shape or method names. One curated entry
exists: `ScopedNativeCallFrame`, cited to `facebook/hermes include/hermes/VM/Runtime.h` at
revision `82f0f971` (the CVE-2020-1896 vulnerable revision — the fix commit doesn't change
this class). Constructor matching is on **parameter count**, not exact type text — a real,
confirmed c2cpg quirk (below) makes exact-type matching unsound.

The analysis logic in `resource_guard_verdict.py` never special-cases the string
`"ScopedNativeCallFrame"` or `"overflowed"` — it reads the contract table generically. The
whole mechanism was exercised, unmodified, against a class named `PlainBuffer` in the
synthetic controls (below) to prove this.

## Verdicts

`RESOURCE_GUARD_MISSING` / `RESOURCE_GUARD_ESTABLISHED` / `RESOURCE_SEMANTICS_UNRESOLVED` —
explicitly **not** a CWE-787 write verdict. A `RESOURCE_GUARD_MISSING` finding is
additionally checked for whether the identified unguarded use is itself the LHS of an
assignment (`downstream_write_evidence`); only then does the finding carry a `cwe_hint`
field at all, worded "CWE-787-shaped (unverified capacity)" — never an outright CWE-787
claim. Connecting an invalid-resource *use* to an actual out-of-bounds *write* is separate,
disclosed evidence, not an assumption.

## Real differential (the actual validation target)

Both fixtures are real Joern v4.0.608 output from real, minimal, single-TU c2cpg exports —
the real function's exact statements, copied verbatim; only surrounding types are stubbed.

- **`study/js_c_transition/raw_case_hermes_apply`** (the vulnerable revision, `82f0f971`,
  already frozen from the earlier js_c_transition measurement) → `RESOURCE_GUARD_MISSING`,
  with `downstream_write_evidence: "direct_assignment_through_resource"`, a `cwe_hint`, and
  the real attacker-influence chain traced end-to-end: `len ← JSArray::getLength(*argArray)
  ← argArray ← args.dyncastArg<JSArray>(1) ← args` (a real parameter of
  `hermesBuiltinApply`), 5 hops.
- **`study/resource_guard/raw_case_hermes_apply_patched`** (the real fix commit,
  `86543ac4`, the exact 3-line guard the fix adds, built fresh for this capability) →
  `RESOURCE_GUARD_ESTABLISHED`.

## The 12 required synthetic controls (`gate_resource_guard.py`, all real Joern facts)

| # | Control | Expected |
|---|---|---|
| 1 | missing check | `RESOURCE_GUARD_MISSING` |
| 2 | correct dominating failure check | `RESOURCE_GUARD_ESTABLISHED` |
| 3 | inverted check (`if (!x.overflowed())`) | `RESOURCE_GUARD_MISSING` |
| 4 | check after first use | `RESOURCE_GUARD_MISSING` |
| 5 | check on a different object | `RESOURCE_GUARD_MISSING` (for the unguarded object) |
| 6 | non-dominating branch check | `RESOURCE_GUARD_MISSING` |
| 7 | alias of the same resource (one-hop reference) | `RESOURCE_GUARD_ESTABLISHED` |
| 8 | unrelated `overflowed()` on an uncontracted class | `RESOURCE_GUARD_MISSING` (for the real object) |
| 9 | infallible RAII object (uncontracted, no predicate) | no finding at all |
| 10 | unresolved constructor semantics (wrong param count) | `RESOURCE_SEMANTICS_UNRESOLVED` |
| 11 | attacker-independent size (a literal) | no finding at all |
| 12 | failure branch that does not terminate | `RESOURCE_GUARD_MISSING` |

All 12 verified to pass with the **correct classification bucket**, not just the correct
final verdict via an accidental fallback — every earlier version of the algorithm that
produced a right verdict for the wrong reason was caught and fixed (see "Design history"
below) before being accepted.

## Design history: three real bugs found and fixed while building this

Each was caught by actually running a control through real Joern facts, not by reasoning
about it — consistent with this project's whole methodology.

**1. Branch polarity via "short, non-branching tail" — proven wrong.** The first version
tried to infer which of a guard's two branch targets was "the failure block" structurally:
the one whose own forward walk was short and never branched before reaching a return. This
broke on `c02_correct_check` (a short synthetic function where *both* branches happen to be
short and linear) — the exact signature can't distinguish `if (cond) return;` from
`if (cond) {...} else return;`, which have *opposite* true/false-to-branch mappings.
Replaced with a directly-verified, **order-based** rule: `resolve_branch_targets()`'s
target list preserves each successor's own file order in `cfg_edges.tsv`; empirically,
across 3 independent real Joern fact sets (`c02`, `c03`, and the real patched Hermes
fixture), the first-listed successor is consistently the "then"/cond-true branch. The
candidate "invalid" branch is then independently sanity-checked via
`resolves_without_touching_object` (catches control 12: a correctly-polarized check whose
failure branch doesn't actually terminate).

**2. Node-keyed clearance — proven wrong by the same control that motivated it.**
`c06_non_dominating_branch` (a guard nested inside an unrelated `if (cond) { <guard> }`)
initially still resolved to `RESOURCE_GUARD_ESTABLISHED`: the outer `if`'s own skip-edge
and the inner guard's valid-edge can converge on the *same* CFG node, and clearance keyed
on "arrived at this node" can't tell those two arrival routes apart. Fixed by keying
clearance on the specific **edge** (source node, in the guard's own pass-through chain →
target) instead of the destination node alone — an edge from the unrelated outer `if`'s own
comparison is never part of the guard's own chain, so it can never satisfy a clearance
edge.

**3. Real c2cpg quirks, each caught by a specific control:**
   - `<operator>.logicalNot` was tracked for negation *counting* but never added to the
     branch-resolution pass-through set, so `c03_inverted_check`'s `if (!x.overflowed())`
     never resolved to exactly 2 targets at all (right final verdict, via a different,
     less-precise code path than intended — fixed).
   - A reference alias's own declared type carries a literal `&` suffix
     (`ScopedNativeCallFrame&`) that a bare `type_full_name == class_name` check doesn't
     match — `c07_alias_use` initially found zero uses at all. Fixed with a shared
     `type_matches()` helper that strips a trailing reference marker everywhere a receiver
     or declared type is compared against a contract's class name.
   - Passing a **literal** argument (`4`) to a `unsigned int` parameter changes c2cpg's own
     recorded `methodFullName` signature text for that parameter to `int` (the literal's
     own inferred type, not the true declared parameter type) — an exact-string constructor
     match would have rejected `c11_attacker_independent_size`'s otherwise-legitimate
     constructor call. Fixed by matching on parameter *count* (derived from the contract's
     citation-backed full signatures) rather than exact type text.
   - `LLVM_UNLIKELY(x)`-wrapped conditions don't give the predicate call a clean 2-successor
     branch directly in this exporter's real CFG output: the macro wrapper call sits at the
     same control-flow position as a duplicate re-emission of the predicate call itself
     (confirmed on the real patched Hermes fixture). `resolve_branch_targets()` treats both
     the macro-wrapper idiom (reusing `lock_balance_verdict.py`'s already-proven
     `branch_point()` logic) and this duplicate-predicate idiom, plus a 1-hop bridge-node
     lookahead for the plain CFG plumbing between them, as pass-through.

## Mining beyond Hermes (what generalization evidence actually exists, and what doesn't)

Per the explicit instruction not to claim this capability generalizes without evidence: two
separate mining passes were run before writing this section.

**Pass 1 — the rest of the existing `js_c_transition` corpus (23 other rows).** Read every
remaining diff in `study/js_c_transition/js_c_transition_corpus.json`'s `js_engine` and
`native_addon` categories (ChakraCore, other Hermes CVEs, JerryScript, njs, SerenityOS
LibJS, MuhammaraJS, detect-character-encoding). **None matches FALLIBLE_BOUNDED_RESOURCE.**
The closest relatives are a different, related-but-distinct pattern — a plain C-style
factory *function* (not a C++ RAII constructor) returning a raw pointer that can be NULL,
checked (or not) by the caller directly, with no separate predicate *method* call on a
constructed object at all (MuhammaraJS's `ParseNewObject()`/`CVE-2022-25892`,
detect-character-encoding's `ucsdet_detect()`/`CVE-2021-39157`). Real bugs, but a shape this
capability's contract schema (constructor + predicate *method* pair) doesn't cover and
wasn't asked to.

**Pass 2 — other real call sites of the SAME curated class, same era.** Grepped the full
Hermes source tree for other uses of `ScopedNativeCallFrame` and found 6 (`Callable.cpp`
×5, `JSLib/Function.cpp` ×2, `JSLib/RegExp.cpp`, `JSCallableProxy.cpp`, `Runtime.cpp`),
all correctly guarded at HEAD (this was never a widespread bug — `hermesBuiltinApply` was
the one function that missed it). Fetched two of these **at the exact CVE-2020-1896
revision** (era-matched, same `ScopedNativeCallFrame` API) and built real fixtures from
them, verbatim, run through the real pipeline:
- `Callable.cpp`'s `executeCall0`/`executeCall1`/etc. use a **literal** size (0, 1, 2, ...)
  — a genuinely different, weaker-evidence case (would correctly hit
  `SIZE_ATTACKER_INDEPENDENT`, not tested as a fixture here since it's not a new shape).
- `JSCallableProxy.cpp`'s `_proxyNativeCall` (`raw_case_hermes_proxy_call`): size from
  `callerFrame.getArgCount()` — a different attacker-influence source than a JS array
  length — and uses `std::uninitialized_copy_n`, not a manual `getArgRef` loop, to fill the
  frame → correctly `RESOURCE_GUARD_ESTABLISHED`.
- `RegExp.cpp`'s replacer-args construction (`raw_case_hermes_regexp_replace`): size is a
  **computed arithmetic expression** (`1 + nCaptures + 2`, attacker-influenced via a
  regex's own capture-group count, not a bare identifier) and uses a for-loop over capture
  groups → correctly `RESOURCE_GUARD_ESTABLISHED`, with `backward_attacker_trace` correctly
  following the arithmetic expression through to the real `nCaptures` parameter (3 hops).

**Honest conclusion:** this capability is validated against exactly **one** real
vulnerability (CVE-2020-1896) and its own fix, 12 synthetic controls, and 3 additional
real, independently-written, currently-bug-free call sites of the same curated class (which
demonstrate the general algorithm — not just fixture-specific tuning — correctly handles
different attacker-influence sources and different use shapes without false-positiving).
It does **not** have independent confirmation of catching a *second* real CVE — the corpus
mined here doesn't contain one, and no claim of broader generalization (beyond this one
class, this one codebase) is made. Extending the curated contract table to other classes,
in other codebases, with their own real evidence, is future work, not implied by anything
here.

## What's out of scope here

- **A second curated contract entry** (a different class, a different codebase) — not
  attempted; the mining pass above found no real candidate in the corpus currently
  available.
- **The plain-factory-function variant** of this same intuition (a C-style function
  returning a fallible raw pointer, no RAII constructor/predicate-method pair) — a related
  but structurally different pattern (see MuhammaraJS/detect-character-encoding above); not
  covered by `resource_contracts.py`'s current schema, which requires both a constructor
  and a same-object predicate *method*.
- **Interprocedural attacker-influence tracing** — `backward_attacker_trace` is bounded and
  same-method-only; its absence never downgrades a non-literal size, and its presence is
  disclosed as bounded evidence, not a full taint proof (see `resource_guard_verdict.py`'s
  own docstring).
- **Double-armed if/else guard shapes** where the order-based polarity rule can't be
  applied unambiguously in the way this capability currently resolves single/branch shapes
  — not hit by any real or synthetic case examined so far, but not proven impossible either.
