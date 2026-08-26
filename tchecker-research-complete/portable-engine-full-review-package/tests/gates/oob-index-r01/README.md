# OOB-INDEX-R01 — new capability (evidence-gated by MOZ-OOB-R01 Row 3)

Adds detection of OOB writes via **indexed stores into fixed-size arrays** (`arr[idx]`, incl.
`arr[idx].field`), the class the frozen memcpy-surface producer misses. Built as a SEPARATE
producer; the frozen analyzer and its 20+ gates are UNCHANGED.

## Result on the MOZ-OOB-R01 corpus (frozen otherwise)
- Row 3 CVE-2022-28281 (WinWebAuthn, rgExtension[1]/sizeof): VULN -> CANDIDATE, FIXED -> suppressed.
  This is the positive control flipping MISS -> CANDIDATE, with the patched version correctly cleared.
- Row 1 (libtremor) and Row 2 (WebGL read): NOT flagged (different shapes — pointer-param runtime
  capacity, and a memcpy read). No false positives.

## Soundness (control matrix, gate_oob_index_r01.py)
FLAG only an indexed store into a fixed-count array `T[N]` (N read syntactically, so OPAQUE element
types like WEBAUTHN_EXTENSION are supported) when the index is NOT provably bounded. SUPPRESS when:
- the index is a constant < N; OR
- the index variable has a direct non-assert upper bound `idx < K` (covers ordinary bounded loops); OR
- the array has a non-assert `sizeof(arr)/sizeof(arr[0])` capacity guard in the function (the fix shape).
Assert-family comparisons (MOZ_ASSERT/assert/NS_ASSERTION) are EXCLUDED — they are compiled out and
do not gate. Emits CANDIDATE only (never VULNERABLE). Per-function scoping via enclosing_function_id.

## Known limitations (honest; recall traded for precision)
- Rule (a) suppresses on ANY direct `idx < K` bound regardless of whether K <= N, so a loop whose
  bound exceeds capacity (e.g. `for(i=0;i<100;i++) buf[i]` on buf[8]) is a FALSE NEGATIVE. Favoring
  no-false-positive is deliberate (the field-read revert precedent).
- Guard analysis is intraprocedural and heuristic (not dominator-based control dependence).
- Does NOT address Row 1 (pointer-parameter runtime capacity) or Row 2 (cross-TU capacity) — those
  remain separate, honestly-scoped gaps.

## Next (still gated on evidence)
Wire this CANDIDATE into the adjudicator/LLM packet (OOB-ADJ-R01), preserving CANDIDATE. Expand
controls before generalizing rule (a) to compare K against N (would recover the loop-bound-exceeds-
capacity FN without introducing FPs — needs its own vuln/patched/safe controls).
