# Semantic-Evidence Bucket Pilot

Small, frozen dry-run pilot for the thesis's semantic-bucket experiment: does
giving an LLM TChecker's structured, deterministic evidence (facts, unresolved
category, provenance, a focused question) improve semantic code review over
giving it raw code alone?

**Status: DRY RUN ONLY.** 8 cases (2 per bucket) x 2 conditions = 16 calls,
run to validate the corpus format, prompt design, and scoring rubric BEFORE
committing to the full 24-case x 2-condition x 3-trial (144-call) experiment.
Per instruction: do not scale up until this dry run's mechanics are confirmed
sound.

## Buckets (2 cases each, dry run; 6 each in the full pilot)

1. **Relationship unresolved** — TChecker established the allocation, the
   write, and the guard's existence/dominance/control-dependence, but one
   specific relationship needed for a verdict cannot be proven from the
   available facts.
2. **Producer evidence missing** — a fact TChecker's analysis would need was
   never exported by the frontend/CPG at all (not a reasoning gap — the raw
   fact simply doesn't exist in the extracted data).
3. **Analysis capability missing** — the evidence needed is visible in the
   source, but TChecker has no model for the required reasoning (indirect
   calls, runtime-configured capacities, cross-iteration accumulation, etc.).
4. **Established controls** — ground truth (safe or vulnerable) is
   independently verified via the public CVE record and official patch diff,
   regardless of what TChecker's own deterministic pass currently concludes.

## Case sourcing and an honest limitation

Every case is grounded in source this session independently verified against
real, disclosed Mozilla NSS or mozjpeg code (see each case's
`verification_notes` and `internal_source_ref` — the latter is stripped from
anything shown to the model). **Known limitation of this dry run**: 6 of the 8
cases come from NSS's `lib/softoken/pkcs11c.c` family or closely adjacent
files. This is acceptable for a MECHANICS dry run (validating that the rubric
and prompt format work at all) but violates the "prefer different repos,
functions, representation shapes" requirement for the real 24-case corpus.
The full pilot MUST diversify beyond this session's NSS-heavy existing
verified material — flagged here rather than silently carried forward.

## Sanitization

Every prompt strips: CVE numbers, commit hashes, git refs, "vulnerable" /
"patched" labels, function or variable names that were renamed specifically
as part of a security fix (e.g. a fix that introduces `checkedSignatureLen`
in place of a plain length variable — the ORIGINAL length variable name is
used in both conditions instead), and comments that explain the security
rationale for a check (e.g. "// Protect against overflow"). Ordinary
pre-existing comments unrelated to the fix are kept, since a real reviewer
would see them too. Case IDs are neutral (`SB-01` .. `SB-08`).

## Conditions

- **raw**: the relevant code only, plus a focused question in plain English
  (no mention of TChecker, no evidence fields).
- **structured**: the IDENTICAL code, plus TChecker's established facts,
  its unresolved-category label, provenance, and the SAME focused question,
  now sharpened with the specific sub-questions the deterministic pass could
  not itself resolve.

Both conditions end with the same required JSON response schema and the same
instruction that the LLM's answer is advisory only and must never
auto-suppress a deterministic candidate.

## Model-call methodology and its limitation

This session has no standalone "raw chat completion" tool — only the `Agent`
tool, which spawns a new subagent with no access to this conversation's
history (satisfies "fresh session, no conversation history"). Each dry-run
call:
- uses a single fixed model (recorded per run),
- is given IDENTICAL framing instructions across both conditions (see
  `prompts/system_instructions.txt`, prepended to every call),
- is explicitly instructed not to use tools and not to seek outside
  information — the case material is fully self-contained,
- has no access to this repository or any other case's material.

**Caveat, stated plainly**: this is an approximation of an isolated API call,
not a true sandboxed inference call — the subagent framework technically
retains tool access even though instructed not to use it. This is recorded as
a methodological limitation of the pilot, to be disclosed in the thesis
writeup, not hidden.

## Files

- `corpus/SB-XX.json` — case metadata, sanitized-code reference, ground truth
  (established BEFORE any model call), and internal verification notes.
- `prompts/SB-XX_raw.txt`, `prompts/SB-XX_structured.txt` — the exact text
  sent for each condition.
- `rubric/scoring.py` — the scoring rubric, dry-run-validated against 2 known
  ground truths per bucket before being trusted on real model output.
- `runs/` — archived prompt, response, timestamp, model version, and a SHA-256
  prompt hash for every call actually made.
- `dryrun_report.md` — the dry run's results and the go/no-go decision for
  scaling to the full 144-call experiment.
