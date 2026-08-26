# Neutral provenance core

Gate 26 introduces the first executable analysis module that consumes `portable.graph.ProgramGraph`
directly and has no dependency on PHP AST classes or WordPress behavior.

Run:

```bash
tests/gates/gate26/run_gate26.sh
```

Current scope: parameter/call/return provenance only. State, aliases, closures, and security
profiles remain outside this module until migrated in later gates.
