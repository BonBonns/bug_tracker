# Real Joern TypeScript frontend boundary

This is the intended first layer for TypeScript. It uses Joern's `jssrc2cpg` and exports standard CPG facts directly; it does not translate TypeScript into PHP AST nodes.

Run the conformance gate:

```bash
JSSRC2CPG=/path/to/jssrc2cpg JOERN=/path/to/joern \
  tests/gates/gate24-ts/run_gate24_ts.sh
```

Do not pass `--no-tsTypes`; the gate is specifically measuring Joern's TypeScript-derived type generation.
