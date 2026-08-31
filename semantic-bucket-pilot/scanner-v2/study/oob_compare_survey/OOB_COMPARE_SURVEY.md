# Task #33: OOB_COMPARE — validate-or-retire investigation

## Question

`oob_compare_verdict.py` (TOR-B2a) has never produced a real corpus positive. Is the detector
broken (retire/rework it), or is it a sound, narrow detector for a real bug shape that is
genuinely rare in this corpus (validate it, leave it gated on real evidence, revisit if/when a
real positive is found)?

## Method

Two independent, real checks, neither fabricated:

1. **Positive-control fixture** (`tests/gates/guard-r01/fixtures/cap_corpus/cmp.cpp`, new): does
   the scanner actually recognize the exact bug shape it claims to, when that shape is present?
2. **Real corpus survey**: of the packages the overnight-diagnostic-100 run actually analyzed,
   how many use `memcmp`/`strncmp`/`CRYPTO_memcmp` at all, and — for every one that does — *why*
   did the scanner not flag it?

## 1. Positive-control result: the detector works

`oob_compare_controls.py` (new, 10/10 passing) runs the real scanner against `cmp.cpp`, built
through the real c2cpg/joern/normalize pipeline (same builder as task #42's `cap_corpus`):

| function | shape | real result |
|---|---|---|
| `cmp_safe` | two-sided safe, literal extent == both capacities | NOT a candidate ✓ |
| `cmp_overrun_b` | extent (16) exceeds side B's capacity (8) only | CANDIDATE, `overruns=['B']` ✓ |
| `cmp_overrun_sizeof` | classic "wrong sizeof" bug: extent is `sizeof(b)` (64) but side A is 8 bytes | CANDIDATE, `overruns=['A']` ✓ |
| `cmp_abstain_var` | extent is a real variable, not compile-time-constant | NOT a candidate (abstain) ✓ |
| `cmp_abstain_pointer` | side B is a pointer parameter, capacity unresolvable | NOT a candidate (abstain) ✓ |

The detector is not broken: given its own exact target shape (a compile-time-constant extent
that structurally exceeds one side's real, resolvable fixed-array capacity), it finds it, and it
correctly abstains on the two dominant real-world shapes (variable extent, unresolved operand)
rather than guessing.

## 2. Real corpus survey: 33 packages use memcmp/strncmp/CRYPTO_memcmp, 0 real candidates

Cross-referencing the overnight-diagnostic-100 run's own real per-package output
(`overnight_diagnostic_working.jsonl`) against the corpus-wide primitive-coverage prescan
(`primitive_search_results.jsonl`, one real `grep`-style hit per package with file/line/text):
**33 of the 100 sampled packages contain a real `memcmp`/`strncmp`/`CRYPTO_memcmp` call site**
(31 `ANALYZED`, 2 `CPP_CPG_FAILED` before reaching the OOB_COMPARE stage). Every single one of
the 31 analyzed packages produced **zero** real `oob_compare_candidates`. Full raw data,
package-by-package, with the exact real source line and file: `corpus_survey.jsonl` (33 lines,
committed alongside this document).

**Root-cause breakdown** (heuristic classification of the 48 real primitive occurrences across
those 33 packages — `abstention_reason_estimate` in `corpus_survey.jsonl`, a source-text
estimate for characterization, not a re-run of the scanner's own AST logic):

| reason | count | example (real, from the survey) |
|---|---:|---|
| Non-constant (variable) extent | 24 | `memcmp(a->metadata, b->metadata, a->metadata_size)` (`@confluentinc/kafka-javascript`) |
| String-literal operand | 15 | `memcmp(buf, "Features", 8)` (`audify`, `@discordjs/opus`) |
| `sizeof(...)` on a dereference/type/arithmetic, not a bare operand name | 7 | `memcmp(pcl, codeloc, sizeof(*pcl))` (`@2060.io/ffi-napi`); `memcmp(line1, line2, sizeof(CHAR_INFO) * length)` (`node-pty`) |
| Literal extent, but an operand is unresolvable (pointer/macro) | 1 | see below |
| `sizeof(TypeName)`, not `sizeof(operand_name)` | 1 | `memcmp(guid_a, guid_b, sizeof(ggml_guid))` (`smart-whisper`) — `ggml_guid` is the *type*, not either compared operand's own name, so it doesn't resolve against either side's capacity |

**Manually cross-verified against real facts (not just the heuristic), the single closest
near-miss**: `@fugood/whisper.node`'s `memcmp(data, vorbis, 6)` (`whisper.cpp/examples/
stb_vorbis.c:1236`). Read directly from the package's own real `cpp_facts.json`: `data` is a
`uint8*` **parameter** (a pointer — capacity genuinely unresolvable, no fixed size in scope),
`vorbis` is a real `uint8[6]` **local** array. The literal extent (6) exactly equals `vorbis`'s
own real capacity — even if `data`'s capacity *were* known, this specific call is not unsafe on
the resolvable side. The scanner's `A is None or B is None: continue` correctly abstains because
`data`'s side is genuinely unknowable from this call site alone, not because of a bug — a sound,
conservative abstention on a real, load-bearing security-relevant call (stb_vorbis is a
real-world audio decoder with its own CVE history), not a missed detection.

## Conclusion

**Validated, not retired.** The detector correctly implements a real, sound, narrow check
(compile-time-constant extent, two-sided fixed-array capacity resolution) and correctly
recognizes the shape when built to trigger it. Real corpus evidence across 33 packages actually
using the primitives this detector watches shows the shape it targets is genuinely rare in
idiomatic C/C++: developers overwhelmingly use variable-length comparisons, compare against
string literals, or use `sizeof()` in forms this conservative reader does not (yet) resolve —
none of which represents a missed real bug this session's diligence surfaced.

**Task #33's own instruction stands**: OOB_COMPARE stays gated (`staged_enablement.py`'s
`ENABLED_PROPERTIES` does not include `oob_compare_candidates`, task #40) until either a real
corpus positive is found or a future, wider corpus run changes this picture. This is not a
permanent retirement — the detector is real and sound, just currently under-evidenced at the
100-package sample size searched here.
