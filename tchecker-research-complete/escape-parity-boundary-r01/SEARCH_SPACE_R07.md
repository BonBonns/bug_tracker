# R07 — traced negatives vs. vacuous ones

`reportable=false`. No security impact, severity or exploitability is assessed.

## What "look into it" turned up

The question was whether the chain layer's `NOT_ESTABLISHED` verdict on the
Mozilla candidate was a defect. Two separate things were tangled together, and
only one of them is.

**Not a defect: the tier's scope.** The reachability tier promotes a candidate
only on a proven *stored text → parser → transform → structured consumer* chain.
An HTTP response header is not stored text, so a MIME parser fed by one cannot
promote. That is the tier's definition, not a bug — the classification is
literally named `DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE`. Widening it to
network-delivered sources would change what the property is. **Not done here.**

**A real defect: the reason strings overstated what was checked.** The chain
reported `NO_STRUCTURED_TEXT_CONSUMER_REACHED`, which reads as "the parser's
output was traced and reaches no structured interpreter." The measured truth on
that unit:

| | count |
|---|---|
| resolved sources in unit | 2 |
| **structured consumers in unit** | **0** |
| logging-only consumers in unit | 5 |
| parser call sites | 1 |
| flow edges computed | 0 |

Zero structured consumers, across 1,528 files. Gecko has its own JSON and XML
parsers and never calls `json_tokener_parse`, `cJSON_Parse`, `xmlReadMemory` or
`sqlite3_exec`, which are the consumers this tier models. So no code whatsoever
could have reached one, and the negative could not have come out any other way.

A negative that could never have come out otherwise is not a finding about the
code. It is a finding about the model's coverage of the code, and the two must
not share a reason string. This is the same defect the parser layer had at R01,
where a control emitting no record at all made "negative" and "never looked"
indistinguishable — now in the chain layer, and firing on the one real chain in
the corpus.

## What R07 changes

Every chain records the search space it failed within, and the reasons split in
two:

| reason | meaning |
|---|---|
| `NO_SOURCE_API_MODELLED_IN_UNIT` | the model does not cover this unit |
| `NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT` | the model does not cover this unit |
| `NO_DELAYED_SOURCE_REACHES_PARSER` | flows were computed and did not connect |
| `NO_STRUCTURED_TEXT_CONSUMER_REACHED` | flows were computed and did not connect |

Neither traced reason is claimed when the parser has no call site at all: with
nothing to trace from, neither statement means anything.

The Mozilla candidate's record now reads:

```json
"reasons": ["NO_DELAYED_SOURCE_REACHES_PARSER",
            "NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT"]
```

Two different claims where there was one. The source half is a genuine traced
negative — two resolved sources existed and neither flows to the parser. The
consumer half is a coverage statement, and now says so.

## A second defect, which I introduced

Committing the corpus results earlier, I deleted `parser_anchors.tsv` to keep
the archive small — 31,863 rows and 5 MB on the Firefox run — and noted that
re-running regenerates it. That was wrong in a way the note did not cover: the
stored facts no longer reproduced the stored findings. Re-deriving the Mozilla
chain from the committed archive reported
`PARSER_NEVER_CALLED_IN_ANALYSED_SOURCE` and `parser_call_sites: 0` for a parser
that was in fact called once.

`run_target.py` now prunes the anchor table to the rows keyed to a finding's
site or method instead of deleting it, so the archive stays small **and**
faithful. The R07 gate reads the real Gecko facts out of that archive, which is
what caught it.

## Controls

`check_search_space_r07.py` — **7/7**. C1 a unit with no modelled structured
consumer says so and does not claim a traced negative (evidenced by the real
1,528-file Gecko facts, not a fixture). C2 a unit that *does* contain modelled
sources and consumers still reports the traced negative when flows genuinely do
not connect, in both languages. C3 every candidate chain carries its search
space. C4 a proven full chain still establishes in both languages. C5 no traced
negative is claimed while the parser is never called. C6 no impact language.

R01 through R06 all still pass.

## What is still not modelled, stated as coverage rather than as a negative

- Network-delivered text is not a modelled source kind. This is scope, not a
  gap, and changing it is a deliberate decision rather than a bug fix.
- Gecko's own structured consumers (its internal JSON and XML parsers, its
  Necko header stores) are not modelled, so no chain through them can establish.
  R07 makes that visible in the record instead of leaving it to look like a
  checked negative.
