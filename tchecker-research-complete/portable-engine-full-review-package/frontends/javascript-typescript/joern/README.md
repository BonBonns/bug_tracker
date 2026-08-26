# Real Joern JS/TS frontend (Gate 24)

This directory supersedes `ts2legacycsv.js` as the intended production first layer.
The old adapter remains only as a regression/prototype oracle for Gates 2–23.

Requirements:
- JDK 21
- Joern distribution containing `jssrc2cpg` and `joern`

Run:

```bash
JSSRC2CPG=/path/to/jssrc2cpg \
JOERN=/path/to/joern \
../../tests/gates/gate24/run_gate24.sh
```

The runner invokes the real frontend, imports the resulting CPG into Joern, exports a
small neutral fact set, normalizes it, and checks the direct-function conformance gate.
