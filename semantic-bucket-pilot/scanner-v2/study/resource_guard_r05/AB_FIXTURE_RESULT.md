# R05 A/B fixture result: the overload-set hypothesis is FALSIFIED

Per direct instruction: "Prove the proposed c2cpg overload-set behavior with a minimal A/B
fixture... confirm only the second becomes unresolved." Four real, compiled (g++ -std=c++17,
verified clean), Joern-run fixtures were built to test this, with increasing precision. **None
reproduced the real failure.** The hypothesis stated in `HDR_FIX_STATUS.md`
("c2cpg's CDT-based frontend fails to resolve a static-factory call whenever the callee
name's overload set contains any template overload") is WRONG as stated, and is corrected
here rather than carried forward silently.

## The four real tests, all showing the SAME (unexpected) result

| Fixture | Structure | Real methodFullName |
|---|---|---|
| `ab_fixture_a_no_template_overload` | `Widget::New(env, len)`, single plain overload | `Widget.New:Widget(env_t*,long)` -- RESOLVED |
| `ab_fixture_b_with_template_overload` | same call site, class also has `template<F> New(env, data, len, F)` | `Widget.New:Widget(env_t*,long)` -- **still RESOLVED** |
| `ab_fixture_c_namespaced_no_template` | fixture A wrapped in `namespace NS` (`NS::Widget::New`) | `NS.Widget.New:NS.Widget(...)` -- RESOLVED |
| `ab_fixture_d_namespaced_with_template` | fixture B wrapped in `namespace NS` | `NS.Widget.New:NS.Widget(...)` -- **still RESOLVED** |
| `ab_fixture_e_conditional_plain_overload` | fixture A + `#ifndef X ... static Widget New(env,data,len); #endif` (mirrors napi.h's real `#ifndef NODE_API_NO_EXTERNAL_BUFFERS_ALLOWED` guard, no template) | `Widget.New:Widget(env_t*,long)` -- **still RESOLVED** |
| `ab_fixture_f_conditional_template_overload` | fixture A + the SAME `#ifndef` guard wrapping BOTH a plain overload AND a template overload -- structurally identical to real `Napi::Buffer<T>`/`Napi::ArrayBuffer`'s own class body | `Widget.New:Widget(env_t*,long)` -- **still RESOLVED** |

Every synthetic isolation attempt -- template overload alone, namespaced, preprocessor-guarded
plain overload, preprocessor-guarded template overload matching real napi.h's exact structural
pattern -- resolved cleanly. None reproduced `<unresolvedNamespace>`.

## A real, additional data point that further disproves the hypothesis

Real node-addon-api's `Error::New` (3 overloads, `static Error New(napi_env, ...)`,
`static Error New(napi_env, const char*)`, `static Error New(napi_env, const std::string&)`
-- confirmed by direct read of `napi.h`, **none of the three is a template**) is ALSO
unresolved for both `Napi::TypeError::New` and `Napi::RangeError::New` in the real Cartesi
run. An overload set containing zero templates still fails to resolve. This alone rules out
"any template overload in the same name's overload set" as the mechanism.

## What real napi.h DOES show, that the fixtures could not isolate

Both `Napi::Buffer<T>` and `Napi::ArrayBuffer`'s real class bodies wrap several of their own
member declarations in `#ifndef NODE_API_NO_EXTERNAL_BUFFERS_ALLOWED ... #endif`;
`class Error : public ObjectReference #if defined(NODE_ADDON_API_CPP_EXCEPTIONS) ... #endif`
has a preprocessor conditional folded directly into its own base-class list (confirmed real
CDT parse problems logged at exactly `napi.h:2053`, inside `Error`'s body, via
`SL_LOGGING_LEVEL=INFO --log-problems`). This pattern looked like a promising, precise
candidate mechanism -- ab_fixture_f reproduces it structurally -- but the fixture still
resolved cleanly, so the REAL header's failure is not explained by this pattern in isolation
either. It most likely depends on the interaction of this pattern with napi.h's own scale
and surrounding complexity (thousands of lines, heavy SFINAE/macro usage elsewhere in the
same translation unit) in a way a ~20-line synthetic fixture does not reproduce -- **this is
stated as an honest, unresolved gap, not asserted as the cause.**

## Why R05 proceeds anyway -- it does not depend on knowing the trigger

R05's own recovery mechanism (see `R05_DESIGN.md`) does NOT require explaining WHY c2cpg
fails to resolve these calls. It depends on a SEPARATE, directly and independently confirmed
property: **the LOCAL/member variable that the call's result initializes carries its own,
independently-resolved `typeFullName`, regardless of whether the initializing call's own
`methodFullName` resolved.** This was confirmed on two real, independent corpus packages
(not just Cartesi):

- Cartesi (`cartesi_test5.cpg.bin`): `Napi::Buffer<unsigned char> data = ...` -> local
  `typeFullName = "Napi.Buffer"` (namespace-qualified).
- `@appthreat/sqlite3` (`sqlite3_proof2/work/cpp.cpg.bin`): multiple real
  `Napi::Buffer<char>` locals resolve to bare `"Buffer"`; multiple real `Napi::ArrayBuffer`
  locals resolve to `"Napi.ArrayBuffer"` (qualified) -- both forms observed for real,
  legitimate node-addon-api usage on the SAME real corpus package.

**Disclosed nuance, not glossed over:** the qualification form is inconsistent between real
sites (bare `"Buffer"` vs qualified `"Napi.Buffer"`/`"Napi.ArrayBuffer"` for the same real
class, across different call sites in the same or different packages) -- R05's own contract
matching (`R05_DESIGN.md`) must accept BOTH forms as equivalent identity evidence for the
same curated type, not just one, and this file records that requirement so it is not lost
when R05 is implemented.

## Further corroborating real data point (from `r05_controls/fixture_source.cpp`)

Building R05's negative-control fixtures surfaced one more real, relevant fact: in a file
that `#include <napi.h>`, even TWO totally UNRELATED classes declared in the SAME file
(`Other::Buffer`, a lookalike; `Widget`, unrelated) -- neither of which is itself part of
node-addon-api -- also resolve their own `::New(...)` calls to `<unresolvedNamespace>`,
exactly like `Napi::Buffer`/`Napi::TypeError` do. Both classes resolved CLEANLY in the
`ab_fixture_*` isolation tests above, which never included real `napi.h`. This corroborates,
rather than newly explains, the "trigger not isolated" conclusion: whatever real napi.h does
that breaks static-factory resolution is not confined to node-addon-api's own types -- it
appears tied to napi.h's own presence/complexity somewhere in the translation unit, degrading
resolution translation-unit-wide. This is recorded as a further real data point, not asserted
as the root cause -- the precise mechanism remains unisolated.
