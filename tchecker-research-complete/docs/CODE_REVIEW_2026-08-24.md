# Code review 2026-08-24 — bugs found

Scope: all Python (190 files, pyflakes + manual), all shell (shellcheck), the gate/
adjudicator logic, producers, and the engine test harness. Findings, most severe first.

## 1. FIXED — tests/run_all.py ran 6 gates twice (copy-paste duplication)
The JS-PROV-R08/R09/R12/R14/R17 block and the SOURCE-R02 block each appeared twice
verbatim. `results` is a list, so every duplicated gate (a) doubled its runtime
(~5-8 min per suite run), (b) inflated the EXECUTED denominator (44 instead of 38),
and (c) double-counted any failure in REGRESSIONS — an env-broken run reported
"15 regressions" for ~8 unique failures. Duplicates removed (commented in-file);
verified: 18 gates invoked exactly once, suite reruns EXECUTED 37/38 with the only
FAIL being finding #2 below.

## 2. OPEN (data loss, not code) — GUARD-R01's /tmp corpora were never captured
guard-r01's oob/bound/capacity live teeth read /tmp/cap_corpus (g.json, t5.json,
sidecars), /tmp/norm_scan, /tmp/sd_scan. NOTHING in any provided archive builds or
contains them — the ef05d8a workspace records (workspace/cpg2..6.bin/project.json)
show they were operator-built Joern CPG corpora whose C sources were never committed.
They transiently existed on this machine earlier today (GUARD-R01 passed 6/6 with all
sub-suites green at ~11:27) and were then lost to /tmp cleanup, after which the suite's
GUARD-R01 fails with FileNotFoundError. Reconstructing the fixtures from the checks'
assertions would be a guess presented as a recovery, so it was not done. ACTION: the
operator should commit the cap-corpus C sources (functions incl. mix_fixed, g_read_ok,
g_write_ok/g_write_lt, nc_b5, nc_b6, teeth_read) plus a builder script into
tests/gates/guard-r01/fixtures/.

## 3. OPEN (harness inconsistency) — controls disagree on missing-fixture behavior
tools/bound_controls.py degrades gracefully when /tmp/cap_corpus is absent (skips live
teeth, shrinking the denominator SILENTLY — "6/6" can mean "static checks only"),
while tools/oob_read_controls.py / oob_write_controls.py crash with FileNotFoundError.
Both behaviors are wrong in opposite directions: silent shrink can hide missing teeth;
crash makes the whole gate report FAIL instead of BLOCKED. Suggested fix: check the
fixture up front and print an explicit BLOCKED line (exit 20, matching run.sh's
convention) in all five control scripts.

## 4. NOTED (suspicious, behavior frozen) — malicious_npm_verdict._suspicious_version
`any(p.isdigit() and int(p) >= 99 for p in parts[:1])` iterates a ONE-element slice:
only the MAJOR version component is tested, so "1.0.999" is not flagged although the
comment says "a single very high component". Defensible for dependency-confusion
heuristics (attacks conventionally bump the major), but the any()-over-[:1] shape
suggests an accidental narrowing. Gate M3 passes either way; left unchanged to keep
gate-verified behavior frozen, flagged for the author.

## 5. NOTED (fragility, documented) — operator-maintained /tmp fixtures generally
/tmp/pp2 and /tmp/cmp2 (GUARD-R01) have no in-repo builder; a stale pp2 caused the
G5 false-failure debugged earlier (see tests/gates/guard-r01/FIXTURE_NOTE.md). All
such fixtures should move under tests/ with builder scripts.

## Clean
- shellcheck: no errors bundle-wide; only benign SC2164/SC2046 warnings.
- No shell=True, no eval on untrusted input, one justified broad except
  (malicious_npm_verdict.analyze_manifest, parsing hostile package.json).
- TSV producers sanitize tab/newline (cl() in export_r38_facts.sc); consumers'
  _rows() count-filtering is safe given that. (.take(120) name truncation is a
  theoretical collision risk, not observed.)
- adjudicate_js.py: hint injection is env-gated (TCH_HINTS) test plumbing; no
  free-text LLM parsing surface. One piece of dead code (subject_step, line 637)
  left from a refactor — harmless.
- pyflakes: remaining hits are unused locals / placeholder-less f-strings in
  historical scripts and error-message strings — cosmetic.
