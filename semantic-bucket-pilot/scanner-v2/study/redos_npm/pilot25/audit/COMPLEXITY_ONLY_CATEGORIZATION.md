# Categorization of the 6 `COMPLEXITY_ONLY` records

Per direct instruction, task 2: "Categorize the six `COMPLEXITY_ONLY` records: genuinely internal
regex; public-export resolution gap; parameter-flow gap; ambiguous call edge; intentional
abstention." Each of the 6 packages was fetched fresh, rebuilt into a real Joern CPG, and run
through the real `export_redos_npm_integ.sc` producer with full diagnostic stderr captured --
never inferred.

| Package | Sink location | Category |
|---|---|---|
| `fuse-napi@2.3.1` | `lib/macfuse.js:5`, `scripts/verify-release.js:100` | `GENUINELY_INTERNAL_REGEX` (macfuse.js case mildly ambiguous, see below) |
| `node-addon-api@8.9.2` | `tools/conversion.js:259` | `GENUINELY_INTERNAL_REGEX` |
| `@depup/node-addon-api@8.9.2-depup.0` | `tools/conversion.js:259` | `GENUINELY_INTERNAL_REGEX` (byte-identical fork of the above) |
| `@h1x4dev/node-addon-api@2.0.0` | `tools/conversion.js:267` | `GENUINELY_INTERNAL_REGEX` (same shape, older tree) |
| `velociradix@8.3.1` | `index.mjs:940` (`Context.graphql`) | **`PUBLIC_EXPORT_RESOLUTION_GAP`** (real design gap, detailed below) |
| `koffi@3.1.6` | `cnoke.cjs:642` (`checkCMake`) | `GENUINELY_INTERNAL_REGEX` |

## The 5 `GENUINELY_INTERNAL_REGEX` cases

All 5 share the same real shape: a dangerous-classified regex lives in a file that is either (a)
never `require()`d by the package's own real runtime entrypoint at all (a standalone install-
lifecycle script, a migration CLI tool, a release-verification script), or (b) reachable only
from an internal error/subprocess-output value the package's own code produces itself, never
from any value a consumer of the package's public API supplies.

- **`node-addon-api`/`@depup/node-addon-api`/`@h1x4dev/node-addon-api`**: `tools/conversion.js`'s
  `sourcePattern.test(filename)`, a Nan-to-node-addon-api migration CLI utility. The file has NO
  `module.exports` at all; the real entrypoint (`index.js`) exports only a static build-config
  object. `@depup/node-addon-api` is confirmed (via `diff -rq`) byte-identical to the upstream
  package's own `tools/`/`index.js` -- same root cause, not independently reviewed twice.
- **`koffi`**: `cnoke.cjs`'s `checkCMake()`, parsing a Windows `reg query` subprocess's own
  stdout to locate a local CMake install -- run only via the package's `install` lifecycle
  script, never from `index.cjs` (the real runtime entrypoint, itself a `require()`-based
  re-export -- the design's own already-documented `INTENTIONAL_ABSTENTION` shape, though that's
  not where this specific sink lives).
- **`fuse-napi`**: two sites. `scripts/verify-release.js`'s `isValidVersion` has no exports at
  all, run only via `prepublishOnly`. `lib/macfuse.js`'s `wrapMacFuseLoadError` IS syntactically
  exported (`module.exports = { MACFUSE_URL, wrapMacFuseLoadError }`, an object-literal shorthand
  the adapter correctly abstains on as `UNRESOLVED_RHS_SHAPE` -- a real, disclosed, unfixed export
  shape gap, see below), but `package.json`'s own `"exports"` map has no subpath exposing
  `./lib/macfuse` externally, the real entrypoint (`index.js`) never re-exports it, and its own
  input traces to a native-binding load failure the package's own code produces internally, never
  a consumer-supplied value. Classified `GENUINELY_INTERNAL_REGEX` on the real reachability
  evidence, with the caveat that a reviewer could reasonably call the export-shape gap itself
  `PUBLIC_EXPORT_RESOLUTION_GAP` on syntax grounds alone -- both are real and disclosed here.

**A real, disclosed, secondary gap surfaced by this review**: object-literal-shorthand exports
(`module.exports = { foo, bar }`) are not one of the adapter's currently-recognized export shapes
(they resolve via `resolveExportRhs`'s catch-all `UNRESOLVED_RHS_SHAPE`, i.e. correctly abstained,
never silently guessed) -- confirmed present in real code (`fuse-napi`'s own `index.js` uses it
for its OWN real public exports too, not just `lib/macfuse.js`). Not attempted here; a real,
distinct future extension, same category of work as the class-export gap below.

## The 1 `PUBLIC_EXPORT_RESOLUTION_GAP` case: `velociradix@8.3.1`

**Real, generalizable design gap, not idiosyncratic to this package.** `Context` (declared
`index.mjs:452`) is genuinely the package's own real public API -- exported via
`export { app, Context, Request, ... }` at `index.mjs:3672`, and `Context` instances are the
`ctx` object every route handler in this framework receives. Its own `graphql()` method
(`index.mjs` around line 900-940) parses `bodyObj.query` (from `JSON.parse(this.req.body...)`)
with a DANGEROUS-classified regex at `index.mjs:940`.

The adapter has **no code path to resolve a class's own instance methods as exported-function
sources at all**: `resolveExportRhs` only handles a bare `MethodRef` or an identifier with
exactly one prior `identifier = MethodRef` assignment; a class declaration desugars to neither
shape (confirmed by the real abstention `exports.Context=UNRESOLVED_IDENTIFIER_NO_METHODREF_
ASSIGNMENT`), so `graphql` never becomes a source-parameter method regardless of how the class
itself is exported. This is a real, distinct capability the adapter's own current design
(deliberately, per its own frozen scope) never attempted: it treats `module.exports = SomeClass`
as `CLASS_CONSTRUCTOR_NOT_PUBLIC_API` (correctly abstaining on the CONSTRUCTOR, since that isn't
the real public surface) but has no complementary path for enumerating an exported class's OTHER
instance methods as sources when the class itself IS legitimately part of the public API (as
`Context` is here, via a named `export {}`, not `module.exports = Context`).

A SECOND, independent blocking gap stacks on top: even if class methods were resolved as
sources, `graphql`'s own tainted value comes from `this.req.body` (an instance field set in the
constructor), not from `graphql`'s own formal parameters -- and the adapter's parameter
enumeration explicitly filters out `this` (`p.method.parameter.filter(_.name != "this")`), by
design, since `this` itself isn't a value a caller directly supplies as an argument. Resolving
class exports alone would not be sufficient without ALSO tracing `this`-field taint from a
constructor's own real parameters through to instance methods -- a further, distinct extension.

**Not attempted here.** Both gaps are real, disclosed, and well-scoped as FUTURE work -- neither
was in the frozen adapter's own documented scope for this first pass, and extending it now would
require the same level of careful, fixture-first validation the original adapter build itself
used, which the "bounded" audit this document is part of does not extend to.

## Recategorization against the second taxonomy (genuinely internal / export gap / flow gap / ambiguous edge / intentional abstention)

Per direct instruction, the same 6 records reclassified using the exact five-category taxonomy
below (dominant real-world cause first; secondary, independently real gaps flagged explicitly
where they co-occur -- see the mechanical decision this table feeds in
`audit/R02_DECISION.md`):

| Package | Sink | Primary bucket | Secondary (co-occurring, real, disclosed) |
|---|---|---|---|
| `node-addon-api@8.9.2` | `tools/conversion.js:259` | `GENUINELY_INTERNAL` | -- (file has no `module.exports` at all; nothing to resolve) |
| `@depup/node-addon-api@8.9.2-depup.0` | `tools/conversion.js:259` | `GENUINELY_INTERNAL` | -- (byte-identical fork, same cause) |
| `@h1x4dev/node-addon-api@2.0.0` | `tools/conversion.js:267` | `GENUINELY_INTERNAL` | -- (same shape, older tree) |
| `koffi@3.1.6` | `cnoke.cjs:642` | `GENUINELY_INTERNAL` | -- (install-lifecycle script, never `require()`d by the real runtime entrypoint) |
| `fuse-napi@2.3.1` (site 1) | `scripts/verify-release.js:100` | `GENUINELY_INTERNAL` | -- (no exports, `prepublishOnly`-only) |
| `fuse-napi@2.3.1` (site 2) | `lib/macfuse.js:5` | `GENUINELY_INTERNAL` (no `package.json` `"exports"` subpath exposes `./lib/macfuse`; real entrypoint never re-exports it; input is internally-produced, not consumer-supplied) | **`EXPORT_GAP`**: `module.exports = { foo, bar }` object-literal-shorthand is not a currently-recognized RHS shape in `resolveExportRhs` (correctly routed to the `UNRESOLVED_RHS_SHAPE` abstention catch-all, never silently guessed) -- a real adapter capability gap independent of the reachability question above |
| `velociradix@8.3.1` | `index.mjs:940` | **`EXPORT_GAP`** (no code path resolves a class's own instance methods as export sources at all -- `Context` desugars to neither the bare-`MethodRef` nor the single-prior-assignment shape `resolveExportRhs` handles) | **`FLOW_GAP`**: even if the export resolved, `graphql()`'s tainted value comes from `this.req.body` (an instance field), not a formal parameter -- `this` is explicitly filtered from parameter enumeration by design, so tracing it would need a second, distinct capability (constructor-parameter-to-instance-field-to-method taint) |

**No `AMBIGUOUS_EDGE` or `INTENTIONAL_ABSTENTION` case among these 6** -- both of those buckets
describe designed, deliberate boundaries of the adapter's own current scope (an unresolved
computed callee, a `require()`-based re-export, multiple candidate assignments) that were not
what stopped any of these 6 records; every one bottoms out in either a real, permanent
unreachability (`GENUINELY_INTERNAL`) or a real, currently-unimplemented capability
(`EXPORT_GAP`/`FLOW_GAP`), not an intentionally-scoped-out shape encountered mid-analysis.

**Mechanical consequence**: `velociradix` alone (`EXPORT_GAP` + `FLOW_GAP`) already satisfies
"any export, flow, or parsing gap -> create R02." `fuse-napi`'s site-2 `EXPORT_GAP`
(object-literal-shorthand exports) is a second, independent, real instance of the same rule,
and both are folded into R02's scope -- see `audit/R02_DECISION.md`.
