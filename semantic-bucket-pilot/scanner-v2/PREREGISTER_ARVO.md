# Pre-registration: ARVO-Meta as the third reachable held-out source

Amendment to PREREGISTER_BIGVUL.md, frozen BEFORE any ARVO mapping/family/pooling output
is computed. Motivation is POWER, not yields: the pooled population after Big-Vul stands
at 11 distinct vulnerable families, one below the pre-registered 12-family gate. Adding a
further complete, pre-registered source under identical frozen rules is sequential corpus
recruitment; no rule from either prior freeze is revisited, and the Big-Vul/PostCutoff
results are already frozen and untouched.

## Dataset identity (pinned)

- ARVO: Atlas of Reproducible Vulnerabilities for Open-Source Software (Mei et al.,
  EuroS&P 2026), metadata + fix patches shipped IN-REPO on GitHub.
- Repo: `github.com/n132/ARVO-Meta`
- Pinned repo commit: `7e1a64f52520a5d63c766d5546a32fd748f23e21`
- Content used: `archive_data/meta/<localId>.json` (project, sanitizer crash_type,
  ARVO-identified fix commit) + `archive_data/patches/<localId>.diff` (the fix diff).
- Why this source: complete and git-accessible; labels are EXTERNAL (ClusterFuzz/
  sanitizer crash types, which distinguish WRITE from READ more directly than CVE CWE
  tags); real fix diffs in-repo — the same localized fix-diff shape the frozen RULE 1
  variant already consumes. Population is OSS-Fuzz bugs, disjoint in provenance from
  CVE-Details-based Big-Vul and from PostCutoff's post-2025 CVE slice; overlap is
  handled by dedup.

## Inclusion (the frozen write-family concept, in this source's label vocabulary)

- `crash_type` must begin with `Heap-buffer-overflow WRITE`, `Stack-buffer-overflow
  WRITE`, or `Global-buffer-overflow WRITE` (the sanitizer expressions of the frozen
  write family: CWE-122/787, CWE-121/787, CWE-787). All READ crash types and all other
  crash types (null-deref, UAF, integer overflow, leaks, timeouts, ...) are excluded.
- Magma-overlap projects removed with the SAME frozen union list as Big-Vul
  (OSS-Fuzz covers Magma targets, so this exclusion does real work here).
- C/C++ diff only, tested with the postcutoff freeze's exact regex on the diff text.
- Unit: one site per meta record (localId), deduplicated within-source by
  (project, fix_commit) and by identical diff sha256.
- ENTIRE meta folder processed in one pass; no early stop at any family count.

## Rules applied UNCHANGED

RULE 1: `postcutoff_freeze.diff_hunk_lines` + `secvuleval_freeze.writes_in`; mapped iff
a UNIQUE (write_kind, dest) across the hunks; ambiguous / no_write_found otherwise; only
mapped sites score; all exclusions preserved. RULE 2: `secvuleval_freeze.family_id`.
Both imported, not reimplemented.

## Pool amendment (pre-registered before the ARVO run)

`pool_heldout_freeze.py` gains ARVO as a third pooled source with the SAME dedup keys:
drop an ARVO mapped site on CVE match (vacuous: ARVO meta carries no CVE ids),
on (project, fix commit) match vs SecVulEval, Magma, or Big-Vul, or on identical
diff_sha256 vs PostCutoff or Big-Vul. Family dedup stays at counting time (distinct
family_id counted once across the whole pool). A same-project ARVO site whose family
coincides with an existing pooled family cannot inflate the family count by
construction. Gate: >= 12 distinct pooled vulnerable families; the honest count is
frozen whatever it is. If the gate is still unmet after ARVO, the result is frozen as
insufficient and any further source requires its own pre-registration; rules are never
revisited to move the count.
