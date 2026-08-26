# JS-STATE-R13 — JS/TS Source Provenance Characterization

**Characterization only. Nothing implemented.** R07/R10/R12 unchanged. No
source detector, no `attacker_controlled` flag, no taint model.

Core question: **can Fable establish that a value originates from an
externally controlled request/input surface without relying on variable
names?**

Names (`req`, `request`, `input`, `body`, `query`, `params`, `username`) are
treated as non-evidence throughout. The critical negative control (T2) is
specifically designed so that name-based reasoning would produce the wrong
answer.

---

## Architectural note (adopted)

R12 independently re-derived the same gap JS-REAL-R01 recorded, which is good
evidence this is a real shared dependency rather than a JS-STATE-specific one.
Accordingly this is characterized as a **general JS/TS provenance capability**,
and the eventual promoted artifact should be a neutral
`ExternalInputOriginFact` — *not* `attacker_controlled = true`. The security
reader decides whether an origin family satisfies its own definition of
attacker control. Such a layer would serve SSRF, path traversal, SQLi, XSS,
prototype-property access, and authentication logic alike.

---

## Framework identity chain — measured link by link

### LINK 1 — import/require identity: **ESTABLISHED**

```text
IMPORT  import express from 'express'
        var express = require("express")
```

Both ESM `import` and CJS `require` forms are captured, with the bound name
tied to the module specifier literal.

### LINK 2 — framework API identity: **ESTABLISHED (and stronger than expected)**

This is the decisive finding. `methodFullName` on the registration call
carries resolved framework provenance:

```text
app.post(...)      mfn = express:<returnValue>:post
router.get(...)    mfn = express:Router:<returnValue>:get
```

and in the real CVE source:

```text
app.post('/auth', ...)   mfn = express:express:<returnValue>:post
                         arg0 ident=app  type=express:express:<returnValue>
```

This is **Joern type-recovery provenance, not name matching**: `app`'s type
resolves back through `express()` to the `express` import. A variable named
`app` that was never assigned from `express()` would not carry this type. This
is exactly the positive evidence required, and it is what makes the old
rejected `function(req, res)` heuristic unnecessary.

### LINK 3 — route registration: **ESTABLISHED**
Registration call sites are ordinary CALL nodes with the route literal
recoverable as an argument (`"/x"`, `"/auth"`).

### LINK 4 — callback identity: **ESTABLISHED**

```text
post arg2 label=METHOD_REF -> prov.js::program:<lambda>0        (inline arrow)
post arg2 label=IDENTIFIER  ident=handler type=prov.js::program:handler   (T7)
```

Inline callbacks resolve directly via `METHOD_REF`. Named handlers passed by
reference (T7) resolve via the identifier's `typeFullName`, which *is* the
target method's fullName — so the forwarding case needs one extra hop but is
fully recoverable.

Real CVE source: `arg2 METHOD_REF -> index.mjs::program:<lambda>4`.

### LINK 5 — parameter role: **ESTABLISHED POSITIONALLY**

```text
<lambda>0  idx0:this  idx1:req:ANY       idx2:res:ANY
<lambda>4  idx0:this  idx1:request:ANY   idx2:response:ANY
```

`<lambda>0` and `<lambda>4` use *different names* (`req`/`res` vs
`request`/`response`) in the *same positions*. Parameter role is therefore
established by **position after the implicit `this`**, entirely independent of
naming — which is the requirement. Note all such params type as `ANY`, so the
type carries no role information; position does.

### LINK 6 — property path: **ESTABLISHED, and families stay separate**

Property reads are recoverable per handler, and the families do **not**
collapse into one undifferentiated "external":

```text
req.body.username     req.params.id      req.headers.cookie
req.cookies.sid       request.query.id
process.env.SECRET    process.argv[2]
```

Each family is a distinct property path off a distinct base, so
`origin_family` can be modelled as a real discriminator rather than a label.

### LINK 7 — destructuring: **FOLLOWABLE**

T3 (`({ body }, res) => ...`) lowers to an explicit assignment:

```text
param idx1 name=param1_0 code={ body }
  ASSIGN  body = param1_0.body
  FIELD   body.username
```

The destructured binding becomes a normal assignment from a field access on
the positional parameter — traceable with existing REF/assignment facts, no
new machinery.

### LINK 8 — local aliasing: **FOLLOWABLE**

T4 (`const body = req.body; use(body.username)`) appears as
`req.body` then `body.username` — a standard assignment chain already covered
by the REF-based propagation used since JS-STATE-R02.

---

## Adversarial teeth — results

| Case | Expected | Measured |
|---|---|---|
| T1 real request source | ESTABLISHED | registration → `METHOD_REF <lambda>0` → idx1 → `req.body.username` ✅ |
| **T2 same names, no registration** | **NOT ESTABLISHED** | `fake` has *identical* params (`req`,`res`,`ANY`) and *identical* property path (`req.body.username`) to `<lambda>0`, but appears as an argument to **no** framework registration call ✅ |
| T3 destructuring | followable | `body = param1_0.body` ✅ |
| T4 alias | followable | assignment chain ✅ |
| T5 wrong parameter | not a request source | reads `res.someProperty` = idx**2**, positionally distinct from idx1 ✅ |
| T6 unrelated `.body` field | NOT ESTABLISHED | `x.body.username` where `x` is a local object literal, not a registered handler parameter ✅ |
| T7 wrapper forwarding | ESTABLISHED via extra hop | `ident=handler type=prov.js::program:handler` ✅ |
| T8 anonymous callback, query family | ESTABLISHED | `router.get` → `<lambda>4` → idx1 → `request.query.id` ✅ |

**T2 is the load-bearing result.** `fake` and `<lambda>0` are byte-equivalent
in every respect a name-based or shape-based heuristic could observe — same
parameter names, same arity, same `ANY` types, same property path. The *only*
discriminator is framework registration. This confirms the discrimination
rests on registration evidence, not on spelling.

---

## R12 anchor replay (real CVE source, not a fixture)

Run against the actual vulnerable commit
(`188f7562…`, `src/tarkov-data-manager/index.mjs`):

```text
SOURCE_FAMILY:        HTTP request body
FRAMEWORK_IDENTITY:   ESTABLISHED — express:express:<returnValue>:post,
                      app typed express:express:<returnValue> via the
                      `import express from 'express'` binding
HANDLER_IDENTITY:     ESTABLISHED — arg2 METHOD_REF -> index.mjs::program:<lambda>4
PARAMETER_ROLE:       ESTABLISHED — idx1 (after implicit `this`), name `req`
                      NOT used as evidence
PROPERTY_PATH:        ESTABLISHED — `let username = req.body.username`
ALIAS_CHAIN:          ESTABLISHED — single assignment, REF-resolvable
SOURCE_PROVENANCE:    ESTABLISHED
```

**The missing link R12 identified is now closed on the real anchor.** The
complete R12 chain becomes:

```text
username  <- req.body.username, req = param idx1 of <lambda>4,
             <lambda>4 registered via express:...:post   [R13: ESTABLISHED]
        v
dynamic property read users[username] on an ordinary object,
prototype reachable, key not provably own, no hasOwn guard  [R12: ESTABLISHED]
        v
runtime lookup domain (STRING|OBJECT) exceeds declared (STRING)  [R12]
        v
abstract equality coercion, operator identity via span recovery  [R10]
        v
authentication decision                                          [R03 sink profile]
```

Every link in the historical CVE is now establishable from real facts.

**This is deliberately not called a detection.** No detector exists; no fact
has been promoted; the chain has been shown *expressible*, which is a
different and weaker claim. Assembling it soundly — with abstention discipline
at each link and negative controls that survive real corpora — is future work.

---

# JS-STATE-R13 VERDICT

```text
FRAMEWORK IDENTITY:              ESTABLISHED (methodFullName carries resolved
                                 express provenance; type-recovery, not names)
ROUTE REGISTRATION:              ESTABLISHED (call site + route literal)
CALLBACK IDENTITY:               ESTABLISHED (METHOD_REF inline; identifier
                                 typeFullName for by-reference handlers)
REQUEST PARAMETER ROLE:          ESTABLISHED POSITIONALLY (idx1 after implicit
                                 `this`; proven name-independent by lambdas
                                 using req/res vs request/response in the same
                                 positions)
BODY/QUERY/PARAM PROPERTY ORIGIN: ESTABLISHED, and families remain SEPARATE
                                 (body / query / params / headers / cookies /
                                 process.env / process.argv all distinct paths)
DESTRUCTURING:                   FOLLOWABLE (lowered to `body = param1_0.body`)
ALIASING:                        FOLLOWABLE (standard REF assignment chain)
R12 KEY CONTROL:                 ESTABLISHED on the real anchor — the gap R12
                                 localized is closed

SOURCE_PROVENANCE_ESTABLISHABLE: YES for framework-registered Express/Router
                                 handlers, on positive structural evidence,
                                 with the name-only negative control (T2)
                                 correctly rejected.

DOMINANT GAP:                    FRAMEWORK COVERAGE, not mechanism. Everything
                                 above rests on Joern resolving the framework
                                 import through to `methodFullName`. This was
                                 verified for Express and Express Router only.
                                 Fastify/Koa/Hapi/NestJS/serverless handlers,
                                 dynamically-registered routes, handlers passed
                                 through middleware wrappers or arrays, and
                                 re-exported handlers are ALL UNMEASURED.
                                 Secondary gap: process.env/argv and
                                 callback/event payload families were observed
                                 as property paths but have no registration
                                 anchor, so they were NOT shown establishable
                                 — only that their paths are distinguishable.

NEXT MILESTONE:                  JS-PROV-R01 — Shared JS/TS External-Input
                                 Origin Layer (characterization, OUTSIDE
                                 JS-STATE). Scope: (1) measure framework
                                 coverage breadth beyond Express before any
                                 implementation; (2) characterize the neutral
                                 ExternalInputOriginFact shape; (3) define
                                 abstention rules so an unrecognized framework
                                 yields UNKNOWN, never "not external". Renamed
                                 out of the JS-STATE namespace deliberately —
                                 if it works it is shared infrastructure, not
                                 a bug-family component.
```

## Discipline note

Every link here was verified against the real CVE source, not only the
fixture, and the one result that would have been easiest to fake — parameter
role — was specifically checked against two handlers using *different
parameter names in the same positions* to prove position rather than spelling
was doing the work. T2 remains the strongest control: name-based reasoning
gets it wrong, registration-based reasoning gets it right.

The temptation to declare the CVE "detected" is noted and declined. R13 shows
the evidence chain is *expressible*; nothing has been assembled, promoted, or
validated against a real corpus, and the framework-coverage gap above means
generalization is currently unmeasured.
