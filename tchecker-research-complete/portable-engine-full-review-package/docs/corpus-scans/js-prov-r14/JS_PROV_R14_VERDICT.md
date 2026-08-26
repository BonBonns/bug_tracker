# JS-PROV-R14 — Module Specifier Resolution (implementation)

`module_export_identity.sc` + `module_specifier_resolution.py` ->
**`ModuleExportIdentityFact`**. JS-STATE untouched.

Closes the link R13 measured as missing:

```text
CALL validate(schema)
  -> imported binding identity        <-- R14
  -> exported symbol identity         <-- R14
  -> validate METHOD
  -> ReturnedFunctionIdentityFact     <-- R12-1 (direct-return only)
  -> validate:<lambda>1
```

## The frontend's callee is overridden, never consulted

R13 measured `m2.validate(1)`, `m3.validate(1)`, `m4.validate(1)` all resolving
to `app.js::program:validate` — a function that does not exist — collapsing
three modules onto one fabricated identity. `identity_evidence` is therefore
`REQUIRE_BINDING+EXPORT_ASSIGNMENT`, and the gate asserts that no fact uses
anything else.

Identity is derived only from explicit program relations: the `require`
specifier literal, the specifier->file path relation, and the target file's
export assignment.

## Fixture: all R13 anchors met

```text
JS_PROV_R14=9/9

m1(1)           -> m1.js  <default>  m1.js::program:other      returned other:<lambda>1
m2.validate(1)  -> m2.js  validate   m2.js::program:validate   returned validate:<lambda>0
m4.validate(1)  -> m4.js  validate   m4.js::program:validate   returned validate:<lambda>0
m3.validate(1)  -> ABSTAIN  NO_MATCHING_EXPORT_MEMBER
```

**The decisive negative passes.** `m1.js` declares both `validate` and `other`,
each returning a different lambda, and exports only `other`. `m1(1)` resolves to
`other` and to *other's* lambda; `validate` is unreachable through it. m2 and m4
resolve to their own modules and do **not** collapse. The object-literal export
(`module.exports = {validate, other}`) abstains rather than guessing.

## Corpus B: the chain reaches the middleware

```text
ModuleExportIdentityFacts: 45
validate(schema) callsites resolved: 9
  validate(schema) -> middlewares/validate.middleware.js
                   -> returned middlewares/validate.middleware.js::program:validate:<lambda>1
```

**9 of Corpus B's `validate(schema)` callbacks now reach `validate:<lambda>1`** —
the exact target R12 could not reach.

### One resolution rule added from measurement

The first Corpus-B run resolved **0** validate callsites: all 176 non-relative
specifiers abstained as external packages. Corpus B uses `app-module-path`, so
`require('middlewares/validate.middleware')` denotes an *internal* file without
a `./` prefix.

Non-relative specifiers are now also tried as **project-root-relative paths**.
This remains a path relation, not a name match, and it resolves only if a file
with an export assignment actually exists there; otherwise the specifier still
abstains. Verified not to disturb the fixture anchors (still 9/9).

## Not yet done

The 9 resolved callsites are not yet fed back into R12's join — `callback_args`
still resolves those arguments to the module. Wiring `ModuleExportIdentityFact`
into callback resolution is the remaining step, and until it lands **Corpus B
state flows remain 0**. No flow counts are claimed here.

# JS-PROV-R14 VERDICT

```text
IMPLEMENTED:                ModuleExportIdentityFact. Evidence is
                            REQUIRE_BINDING+EXPORT_ASSIGNMENT only; the
                            frontend's fabricated callee is overridden.
FIXTURE:                    JS_PROV_R14=9/9, all R13 anchors met.
DECISIVE NEGATIVE:          PASSES — m1 -> other, never validate.
NO-COLLAPSE:                PASSES — m2/m4 keep distinct identities.
OBJECT-LITERAL EXPORT:      ABSTAINS (member identity not exposed at BLOCK level).
CORPUS B:                   45 facts; 9 validate(schema) callsites reach
                            validate:<lambda>1.
REGRESSIONS:                R07 31/31, R08 12/12, R09 11/11, R12 14/14.
CORPUS-B STATE FLOWS:       still 0 — R14 is not yet wired into callback
                            resolution. Not claimed as closed.
DOMINANT GAP:               Feed ModuleExportIdentityFact into callback_args so
                            R12's join consumes the resolved middleware.
NEXT MILESTONE:             JS-PROV-R15 — Wire export identity into callback
                            resolution, then re-run the R12 join on Corpus B.
                            Acceptance: R12 fixture stays 14/14, R14 stays 9/9,
                            and Corpus B produces per-property flows
                            (validatedData.email -> HTTP_BODY distinct from
                            validatedData.user -> DB_LOOKUP).
```

## Discipline note

The root-relative rule was added because measurement demanded it, not to make a
number move: without it Corpus B resolved zero validate callsites, and with it
the fixture anchors are unchanged. It is deliberately conditional on a real file
with a real export assignment existing at that path, so a genuine external
package still abstains rather than being mapped onto a coincidentally-named
local directory.

Corpus B state flows are still reported as **0**. R14 resolves the identity; it
does not yet deliver it to the join, and reporting flows now would credit work
that has not been done.
