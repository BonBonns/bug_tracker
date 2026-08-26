# Gate 2 continuation — real-engine JS call graph now resolves

## Result
The earlier diagnosis that `createFunctionCallEdges()` required a PHP Spider/path2callee input was incorrect for ordinary named function calls. The existing fallback name resolver already works for JavaScript-shaped `AST_CALL` nodes once the CSV AST contract is satisfied.

Run result on the real compiled engine:

- `ANALYSIS_STATUS=COMPLETE`
- functions discovered: `sink_f`, `middle_f`, `main`
- resolved call edges:
  - `middle_f -> sink_f`
  - `main -> middle_f`
- generated `call_graph.csv`:
  - `20 -> 6  CALLS`
  - `38 -> 20 CALLS`

No engine behavior change was required.

## Actual blockers found

### 1. `FILE_OF` is an edge-stream sentinel
`CSVFunctionExtractor.addEdgeRowsUntilNextFile()` stops reading the current file as soon as it encounters `FILE_OF`. The adapter originally emitted `FILE_OF` before its `PARENT_OF` edges, so none of the AST wiring was interpreted. Functions were discovered from node rows, but calls had `targetFunc == null`.

Fix: emit `FILE_OF` after every AST edge for the file.

### 2. AST edges must be child-first
The edge interpreter attaches fully-built child objects to parents. For a call, `AST_NAME -> string` must be processed before `AST_CALL -> AST_NAME`; otherwise `Identifier.getNameChild()` is null while `handleCall()` executes.

Fix: emit/reorder `PARENT_OF` edges child-first. The adapter now reverses its construction-order AST edges before writing them.

### 3. Fixed-arity PHP AST nodes require NULL placeholders
`AST_PARAM` is treated positionally as `[type, name, default]`, and downstream DDG code reads `getChild(1)` for the parameter name. Emitting only the name makes it child 0 internally even if its CSV `childnum` says 1.

Likewise `AST_FUNC_DECL` is treated as `[params, uses=NULL, stmts, returnType=NULL]`.

Fix: emit the missing NULL children at the expected positions.

### 4. The fixture name `test.js` triggered the existing test-code filter
`addCallEdge()` rejects definitions when `filterTest(getDir(functionDef))` identifies the path as test code. With the fixture named `test.js`, the resolver found `sink_f`/`middle_f` and returned from lookup, but intentionally refused to add `call2mtd` edges.

Fix for the portability fixture: use `gate2.js`. This is existing engine semantics, not a JS call-resolution defect.

## What is now established
The real PHP engine can consume JavaScript-derived `nodes.csv`/`rels.csv`, build CFG/DDG facts, discover functions, and resolve ordinary named JS function calls using the existing call resolver. The portability boundary is therefore smaller than previously thought: ordinary free-function call resolution does not require a new JS-specific resolver.

## Still open
- methods/classes/dynamic dispatch in the real engine adapter
- TypeScript type narrowing
- a neutral way to represent frontend resolution quality for dynamic calls
- whether the legacy test-file exclusion should remain a core policy or move into a frontend/project profile
