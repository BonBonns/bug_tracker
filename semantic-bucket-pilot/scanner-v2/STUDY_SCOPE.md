# Scope — this A/B/C is a SINGLE-BUCKET (`length_meaning`) review evaluation

All **438** LLM-eligible case instances belong to **one** semantic bucket:
`unresolved_property = length_meaning` (route `semantic_relationship_review`). The
routing study's other route, `range_arithmetic_review` (68 ops), is not LLM-eligible
and is not in this population; no other bucket appears.

**Consequence:** this A/B/C experiment does **not** test whether *multiple* semantic
buckets improve LLM review, and does not test the system's ability to **select among**
buckets. Because the category is constant across every case, any `C − B` effect
mostly reflects the **focused relationship question** for length relationships, not
bucket selection.

## The honest question this experiment answers

> For **unresolved buffer-length relationships**, does a category-and-focused-question
> interface (C) outperform a **generic, length-matched** review instruction (B) when
> the established facts are held constant?

## Two-part thesis structure

1. **Routing evaluation** (`ROUTE_TRANSITION_MATRIX.md`, `EVIDENCE_TRACE.md`): tests
   the broader causal taxonomy across different reasons and routes — how consuming
   stack-capacity evidence moves operations among routes. This is where the
   multi-bucket / routing claim lives.
2. **A/B/C review experiment** (this study): tests the **`length_meaning` bucket's
   focused interface** on one homogeneous case population. Single bucket.

## Do NOT generalize

Results of this A/B/C experiment must **not** be generalized to other buckets or
routes — `path_feasibility_review`, `semantic_contract_review` (external contracts),
`destination_identity_ambiguous` (identity ambiguity), `range_arithmetic_review`, or
"bucket-guided review" in general. The supported claim is confined to focused review
of **unresolved length relationships**.

## If a general "bucket-guided review" claim is wanted

To support a general claim, **independently-grounded cases from several LLM-eligible
categories** must be added to the corpus **before** freezing the confirmatory split —
which would reopen the frozen capability-effect corpus and change the target
population. That is not done here. As frozen, the experiment is titled a
**single-bucket (`length_meaning`) evaluation**, and every write-up must carry that
title.

## Tokenizer honesty (related)

Prompt length matching between B and C is currently verified with a **declared proxy
tokenizer**, not the fixed model tokenizer (`PROMPT_CONDITIONS.md`,
`study/prompts_FROZEN.json`, `authoritative=false`). Before Stage 2, use the fixed
provider's token-count facility or actual input-token metadata; if authoritative
counts remain unavailable, retain the proxy, report it transparently **with the
char/word counts**, and do **not** call it exact tokenizer matching.
