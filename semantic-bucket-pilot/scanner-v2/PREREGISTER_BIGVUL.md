# Pre-registration: Big-Vul (MSR'20) as the second reachable held-out source

Frozen BEFORE any mapping, family, or pooling output is computed. No model calls,
no TChecker, no manual per-site interpretation. Committed prior to the first run of
`bigvul_freeze.py`; no yields inspected at pre-registration time.

## Dataset identity (pinned)

- Big-Vul, MSR 2020 (Fan, Li, Wang, Nguyen: "A C/C++ Code Vulnerability Dataset with
  Code Changes and CVE Summaries"), commit-level release shipped IN-REPO on GitHub.
- Repo: `github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset`
- Pinned repo commit: `6022ca320b2204baa6ae1ba50e6564b717a8be51`
- File: `all_c_cpp_release2.0.csv`
- sha256: `02970f6d07f22dcff4f03983a89b1fd68bebb63289eaa98f4c7e11d6218d907c`
- Why this source: complete and git-accessible (HuggingFace remains 403-blocked in this
  environment; Google-Drive-only artifacts such as Big-Vul's function-level split are NOT
  git-accessible and are not used). External labels are CVE Details entries joined to real
  fix commits; each row carries the per-file unified-diff patches (`files_changed`, JSON
  objects joined by the literal separator `<_**next**_>`). CVE period 2002-2019 — disjoint
  by construction from PostCutoff-CVE's post-2025 time slice; overlap with SecVulEval is
  possible and handled by dedup (below).
- Corpus construction is scanner-independent: no verdict-producer code is imported, so the
  parallel verdict-code branch state cannot affect which externally labeled sites qualify.

## Unit of analysis

One site per distinct `(cve_id, commit_id)` row (in-dataset duplicates counted and
dropped). The site's source text is the concatenated unified-diff patches of its C/C++
files (`filename` matching `\.(c|cc|cpp|cxx|h|hpp)$`) — the same localized fix-diff shape
the PostCutoff freeze consumed.

## Rules applied UNCHANGED (imported from the frozen modules, not reimplemented)

- RULE 1 (exact write-site mapping), PostCutoff diff variant: `diff_hunk_lines` from
  `postcutoff_freeze.py` + `writes_in` from `secvuleval_freeze.py`; a site is `mapped`
  iff exactly ONE unique `(write_kind, dest_expr)` exists across the hunk lines;
  `ambiguous` if more; `no_write_found` if none. Only `mapped` sites score. Ambiguous and
  no-write sites are excluded and PRESERVED as exclusions (never revisited), exactly as
  the existing 34 ambiguous / 57 no-write PostCutoff exclusions are preserved.
- RULE 2 (family assignment): `family_id` from `secvuleval_freeze.py` over the hunk body
  and the mapped write. Frozen now; never recomputed after any scanner output is seen.

## Inclusion rules (identical to the PostCutoff freeze)

- `cwe_id` in the write family {CWE-787, CWE-122, CWE-120, CWE-121, CWE-124, CWE-680,
  CWE-805, CWE-806}. Read CWEs (125/126/127), CWE-119 (read-or-write ambiguous), and all
  other CWEs are excluded by not being in this set.
- Magma-overlap projects removed: union of the two frozen lists
  (`secvuleval_freeze.MAGMA_PROJECTS` by project name; `postcutoff_freeze.MAGMA_REPOS`
  by repo basename), matched case-insensitively against Big-Vul's `project` column.
- C/C++ patches only (rule above); rows whose fix touches no C/C++ file are excluded.
- ENTIRE dataset is processed in one pass. No early stop at any family count.

## Cross-source deduplication (Big-Vul mapped sites vs the three existing sources)

A Big-Vul mapped site is DROPPED from the pool if it matches any existing source's site by:
1. CVE id (vs PostCutoff `cve`, SecVulEval `cve`);
2. (project, fix commit): `(project.lower(), commit_id)` vs SecVulEval
   `(project.lower(), commit_id)` and vs Magma catalog `(tgt, commit)`;
3. source site: identical `diff_sha256` vs PostCutoff site `diff_sha256`;
4. Magma projects are already excluded wholesale at inclusion time (Magma's frozen
   artifacts carry no CVE ids, so project-level exclusion is the Magma dedup mechanism,
   consistent with both prior freezes).

Proof-obligation family dedup applies at COUNTING time: the pooled family count is the
number of DISTINCT `family_id`s across the pooled mapped-vulnerable sites; a family
present in more than one source counts once. For transparency the pooled manifest also
flags which pooled families coincide with the structural families of Magma's 7 mapped
development bugs (computed with the same frozen `writes_in` + `family_id` on the frozen
`write_mapping.json` records) — flagged, not excluded, matching the prior freezes'
repo-level (not family-level) Magma exclusion.

## Pooled population and gate

- Pool = PostCutoff mapped vulnerable sites (21, 9 families — unchanged) ∪ Big-Vul mapped
  sites surviving dedup (all Big-Vul rows are vulnerability fixes, so mapped = vulnerable).
- The SecVulEval reachable pilot stays a pilot; its 2 vulnerable families are already
  structurally contained in PostCutoff's 9 and it contributes dedup constraints only.
- Gate: >= 12 distinct pooled vulnerable families. The honest count is frozen whatever it
  is; no rule may be revisited afterward to move it.

## Ordering constraints (frozen)

Branch reconciliation onto one definitive scanner commit happens AFTER this pooled freeze
and BEFORE any held-out scanner measurement, so the measured scanner version is
unambiguous. Capability 2 begins only after all gates pass on the reconciled commit.
