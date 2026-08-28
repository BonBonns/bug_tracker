# A/B/C prompt conditions — length-matched, evidence-held-constant

**Scope: single bucket `length_meaning`.** All 438 cases are one bucket, so `C − B`
tests the focused length-relationship interface, not bucket selection
(`STUDY_SCOPE.md`).


`C − B` must isolate TChecker's bucket-guided **category-and-question interface**,
not raw verbosity. If C adds a category and a focused question while B only says
"review this", a C advantage could come from greater prompt length, more directed
attention, or more detailed instructions — none of which is the intended interface.
So **B is a token-matched generic baseline**: same facts, same schema, a generic
instruction of comparable size, and **only C** carries the causal category and the
relationship-specific routing.

Status: **prompts drafted and length-matched under a proxy tokenizer; authoritative
token verification pending.** With the fixed model tokenizer unavailable in this
environment, `verify_prompt_tokens.py` ran a declared word+punctuation proxy: B =
69 tokens, |C−B| median 3 / max 5 tokens, **100% of instances within a 12-token
tolerance** (`study/prompts_FROZEN.json`, `authoritative=false`). The mechanism and
the length match hold; the **authoritative** freeze must re-run with the fixed model
tokenizer and re-confirm the tolerance **before any A/B/C model call**. Stage 1
labeling is unaffected — its neutral reference packet is condition-independent.

## Shared across all conditions

- **Same code** context (the enclosing function source + the highlighted operation),
  identical bytes for A/B/C.
- **Byte-identical established facts** for B and C (destination capacity, write-length
  expression, guards, reachability). A does not receive the facts block.
- **Same response schema** (identical for A/B/C):

      { "conclusion": "vulnerable | safe | unresolved",
        "rationale": "<free text citing the evidence used>" }

  `unresolved` is a first-class answer; the schema and its wording are byte-identical
  across conditions.

## Instruction blocks (the only thing that varies)

**A — code only, generic instruction.**
> Review the highlighted operation in the code above. Decide whether it is
> vulnerable, safe, or whether the evidence is insufficient to establish either, and
> explain which parts of the code support your conclusion.

**B — facts + GENERIC, length-matched instruction.** (Facts block, then:)
> Review the highlighted operation using the established facts above. Consider the
> destination, the write length, and any conditions that guard the operation, and
> assess carefully whether the write could exceed the destination on some reachable
> execution of this code. Then decide whether the operation is vulnerable, safe, or
> unresolved, and identify any relationship that remains unresolved in the evidence
> provided.

B is deliberately generic — it names no routing category and asks no
relationship-specific question — but is sized to match C's category+question so the
instruction-token counts are comparable.

**C — facts + bucket-guided category AND focused question.** (Same facts block, then:)
> Review the highlighted operation using the established facts above. TChecker routed
> it to the category **`{uncertainty_category}`**. Answer the focused question:
> **`{focused_question}`** — then decide whether the operation is vulnerable, safe, or
> unresolved, and explain which established facts support your conclusion.

B and C share the identical facts block and schema; B's generic direction is written
to be close in size to C's category+question so the **instruction-token counts
match** within tolerance. Only C contains `{uncertainty_category}` and
`{focused_question}` — the causal routing content.

## Freeze + verification rule (`verify_prompt_tokens.py`)

Before any A/B/C model call, freeze and verify, using the **fixed model tokenizer**:

- **same code** (byte-identical across A/B/C) — hashed;
- **byte-identical facts** (B vs C) — hashed;
- **same response schema** (byte-identical across A/B/C) — hashed;
- **comparable instruction length**: `|tokens(C_instruction) −
  tokens(B_instruction)| ≤ TOLERANCE`, computed per instance and reported as a
  distribution, with the **tokenizer name/version, per-instance counts, and
  tolerance** recorded in `study/prompts_FROZEN.json`. Use the **fixed provider's
  token-count facility or actual input-token metadata**. If authoritative counts are
  unavailable, retain the declared proxy, report it transparently, and **also report
  char/word counts** — do **not** call it exact tokenizer matching;
- **only C** contains the category and the relationship question (A and B must not).

Current state: length-matched under a declared proxy (`authoritative=false`) — B = 69
proxy tokens / 416 chars / 60 words; |C−B| token median 3 / max 5, char median 19 /
max 42, word median 3 / max 4, 100% within the 12-token tolerance. The authoritative
freeze must re-run with the fixed provider's tokenizer before A/B/C calls.

## Correct description of the comparison

> `C − B` measures the effect of replacing a **generic, length-matched review
> instruction** (B) with TChecker's **bucket-guided category-and-question interface**
> (C), with the code and the established facts held byte-identical. It does not
> isolate the bucket label alone (C bundles category + question), and it is not a
> verbosity effect (instruction-token counts are matched within tolerance).
