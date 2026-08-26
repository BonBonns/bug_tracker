# Portable ProgramGraph API — Gate 25

This module is the language-neutral boundary between any frontend (Joern PHP, Joern
JavaScript/TypeScript, future Python/Java/Go frontends) and the portable analysis
core. It intentionally contains no PHP AST node kinds and no WordPress concepts.

The JSON interchange schema is `portable-program-facts/0.2`. The Java API is a
small immutable view over the same concepts.

Resolution classes are semantic evidence classes, not parser dispatch kinds:
`EXACT`, `HEURISTIC`, `AMBIGUOUS`, `UNRESOLVED`.
