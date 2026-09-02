# NPM-SOURCE-IDENTITY-R02: restoring the Meteor.methods / message-item ingress vocabulary

## Why this round exists

R01's own header comment deliberately scoped the `(message|item)` Meteor/RocketChat-specific half
of `export_redos_npm_integ.sc`'s own ingress model out of the shared module, calling it "sink-
adjacent application vocabulary out of this property-neutral producer's own scope." That call
turned out to be too aggressive: when Path Traversal's own next revision (R02) was built to
consume this module's `source_origin_facts.tsv` instead of re-deriving its own source
classification, real testing surfaced that **18 of the 26 real fixtures in
`fixtures/path_traversal_r01/src/`** use `Meteor.methods` registration, not `req`/`request`
field-access, as their own `APPLICATION_INGRESS_INPUT` source — confirmed directly:

```
$ grep -lc "Meteor.methods" fixtures/path_traversal_r01/src/*.js | wc -l
18
$ grep -lE "req(uest)?\.(body|query|params|headers|payload|url)" fixtures/path_traversal_r01/src/*.js | wc -l
4
```

Under R01's own narrower vocabulary, those 18 fixtures would have silently lost ALL source
recognition the moment Path Traversal migrated to this module — not a cosmetic gap, a real
regression in the property's own coverage. This module had not yet been consumed by any merged,
production wiring when this was discovered (ReDoS's own pipeline wiring, merged separately, still
uses its own standalone `resolveExportRhs`/`SOURCE_PATTERN` logic directly, never this module) —
so extending it now, before Path Traversal R02 becomes its first real consumer, carries zero
regression risk to anything already shipped.

## What was added

`producers/export_npm_source_identity_r02.sc` (new file; `export_npm_source_identity.sc`, R01,
stays byte-for-byte frozen, per this project's own established R01→R02 convention):

1. **`MESSAGE_SOURCE_PATTERN`** (`(message|item)\.(urls|text|attachments)(\..*)?`) — ported
   verbatim from `export_redos_npm_integ.sc`'s own frozen pattern. Same field-access mechanism as
   the existing `req`/`request` pattern (structural CPG matching, never literal-text matching).
2. **`meteorIngressParams()`** — ported, structurally unchanged, from
   `export_path_traversal_integ_r01.sc`'s own `findIngressParams`: finds `Meteor.methods({...})`
   registration calls, walks the registration object-literal's own property assignments, resolves
   each registered handler name via either a direct `Identifier` reference or a `MethodRef`, then
   collects that resolved method's own non-`this` parameters as real ingress sites. Wired into the
   site-hit loop with the SAME real-identity discipline the `PACKAGE_API_INPUT` loop already used
   (a candidate identifier is matched by name for performance, but only credited when its own
   `resolveIdentity()` root is EXACTLY the registered parameter's own id — never name-matching
   alone, so an unregistered function sharing a parameter name is never conflated with a
   registered one).

Output schema is completely unchanged (still `site_id, file, line, site_code, origin_family,
family_detail, multi_origin, origin_count`) — this is a pure additive extension of WHICH real
sites get recognized, never a new column or a new file.

## Real evidence

**The regression, reproduced and fixed** — R01 vs. R02 shared producer run side-by-side against
Path Traversal's own real 26-fixture set (same CPG, both producers):
```
R01: source_origin_facts rows: 17 (sites=17, multi_origin_sites=0)
R02: source_origin_facts rows: 53 (sites=53, multi_origin_sites=0)
```
36 of R02's new rows carry `family_detail = "Meteor.methods-registered handler parameter ..."`,
e.g.:
```
68719476739  ctrl01_sibling_prefix.js       9  userPath  APPLICATION_INGRESS_INPUT  Meteor.methods-registered handler parameter userPath  false  1
68719476779  ctrl05_aliased_fs_import.js    8  userPath  APPLICATION_INGRESS_INPUT  Meteor.methods-registered handler parameter userPath  false  1
```

**Both real Meteor.methods registration shapes recognized**, on this round's own new
`fixtures/npm_source_identity_r02/src/cap8_meteor_ingress.js`:
```
68719476816  cap8_meteor_ingress.js  12  userInput  APPLICATION_INGRESS_INPUT  Meteor.methods-registered handler parameter userInput  false  1
68719476817  cap8_meteor_ingress.js  17  userPath   APPLICATION_INGRESS_INPUT  Meteor.methods-registered handler parameter userPath   false  1
```
Line 12 (`referencedRegistration: referencedHandler`) is the Identifier-reference shape; line 17
(`directRegistration: function (userPath) {...}`) is the inline function-literal/MethodRef shape.
The file's own UN-registered `directHandler(userPath)` (a real, different `MethodParameterIn`,
same name) produces zero rows — confirmed real identity resolution, not name-matching.

**message/item pattern**, on `cap9_message_item_ingress.js`:
```
30064771147  cap9_message_item_ingress.js   7  message.text       APPLICATION_INGRESS_INPUT  message/item field-access pattern  false  1
30064771148  cap9_message_item_ingress.js  11  item.attachments   APPLICATION_INGRESS_INPUT  message/item field-access pattern  false  1
```

**Zero regression on R01's own fixture set**: R02's own copy of R01's 14 synthetic fixtures
reproduces every one of R01's own 18 `source_origin_facts.tsv` rows unchanged (compared by real
file/line/code/family content, since a different combined CPG assigns different internal node
ids to the same content) — R02 only ADDS rows, never removes or alters existing ones.

**Zero regression, zero spurious matches on real, unrelated code**: R02's own real dev-package run
(motifer/logify/miniml/ms — logify's `dist/` contents flattened per this project's own already-
documented jssrc2cpg-ignore-rule workaround) is **byte-for-byte identical** to R01's own committed
`raw_real_packages/` baseline across all three output files (`source_origin_facts.tsv`,
`closure_identity.tsv`, `export_surface.tsv`) — confirming both that nothing broke, and that none
of these 4 real packages spuriously trip the new Meteor/message-item vocabulary (correctly: none
of them are Meteor or RocketChat packages).

**Determinism** re-verified directly on the R02 fixture set (not merely re-asserted from R01,
since R02 adds new code paths): two independent runs, diffed byte-for-byte, zero differences.

## Regression suite

`semantic-bucket-pilot/scanner-v2/check_npm_source_identity_r02.py`: **12/12**.

## Scope

Standalone; not yet wired into any property's pipeline. Path Traversal R02 (in progress on
`feature/path-traversal-r02`) is this module's first real consumer and will read
`source_origin_facts.tsv` from whichever revision of this producer was run against a given CPG —
its own consumption code needs no changes for this extension (same schema).
