# Mechanics dry run (DEVELOPMENT-ONLY)

Step 1 of the corpus plan: validate that the A/B/C experimental machinery works,
using the 5 independent development cases from the frozen llm-eligible corpus.

**These 5 cases are development-only. Their results NEVER enter the confirmatory
accuracy statistics.** The dry run tests the harness, not the hypothesis. The
confirmatory experiment runs on a separately-expanded, independently-verified
corpus (Step 2/3), with fresh orderings.

## What this validates

| mechanic | how |
|----------|-----|
| prompt generation | `generate_dev_prompts.py` builds A/B/C for each case from the frozen `bucket_router` (facts + category + question are auto-derived, not hand-written) |
| **byte-identical B/C evidence** | asserted in code: B and C share an identical prefix; C differs ONLY by the inserted two-line category/question block; removing it from C reproduces B exactly |
| blinding + randomization | `build_run_manifest.py` shuffles the 15 (case×condition) tasks under a fixed seed and hides case/condition/ground-truth behind opaque `blind_id`s (`blind_key.json` sealed until scoring) |
| running the reviewer | one naive subagent per blinded prompt; sees only its prompt, writes a JSON verdict |
| output parsing | `score_dev.py` parses each response (tolerant of fences/prose), flags parse errors |
| scoring | classification vs hand-verified ground truth; `unknown` treated as abstention (correct only when ground truth is itself `unresolved`) |
| archival | every prompt (`archive/tasks/`, `archive/*.txt`), the manifest, the sealed key, every raw response (`archive/responses/`), and the scores are kept |

## Cases (development-only)

| case | ground truth | scanner bucket |
|------|--------------|----------------|
| rsa_vuln / rsa_patched (CVE-2019-17006) | vulnerable / safe | relationship_unresolved |
| mjpg_encode_vuln (mozjpeg) | vulnerable | relationship_unresolved |
| sftk_kdf_safe (incidental) | safe | relationship_unresolved |
| nsc_pbe_unresolved (incidental) | unresolved | relationship_unresolved |

`sec_asn1d_add_to_subitems` (external_contract_unknown) is intentionally
excluded: the frozen `bucket_router` has no Condition-C question template for
that bucket, so it can't be rendered without a router change (a new
experimental version). Recorded as a limitation, not worked around.

## Reproduce

```sh
python3 generate_dev_prompts.py     # build + assert B/C identity
python3 build_run_manifest.py       # blind + shuffle (seed 20260827)
# run one reviewer per archive/tasks/<blind_id>.txt -> archive/responses/<blind_id>.json
python3 score_dev.py                # parse + unblind + score
```

## Honest limitation restated

All five cases sit in one bucket (`relationship_unresolved`). The dry run
therefore proves the pipeline runs and scores; it cannot exercise B-vs-C across
bucket variety, because the frozen llm-eligible corpus does not contain that
variety (see `../FEASIBILITY.md`). That is the reason for Step 2 (corpus
expansion) before any confirmatory A/B/C claim.
