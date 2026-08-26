# Fixes applied 2026-08-26 (fresh sandbox run)

This bundle was extracted and run end-to-end in a fresh sandbox (Layer 1 hermetic +
Layer 2 with a freshly-downloaded, pinned Joern v4.0.608). Two real defects were found,
fixed, and re-verified; a third item (`GUARD-R01`) was confirmed to be a pre-existing,
un-reproducible fixture loss, not a code bug, and is now labeled accordingly instead of
counting as a regression.

## 1. `SOURCE-R02` — `MEMORY` / `MEMORY_LOCATION` enum mismatch (real bug, fixed)

**Symptom:** `SOURCE-R02` failed 6 of its 13 teeth (K1, K3, K4, K5, H5, H6), all showing
`[None]` — as if the engine had produced no sink-resolution output at all.

**Root cause:** `SourceOriginFact.TargetKind` (Java enum, `core/program_graph/.../SourceOriginFact.java`)
declared its memory-location case as `MEMORY`. Every JSON producer
(`normalize_c_cpp_facts_v03.py`) and the Python test oracle (`check_source_r02c2.py`) had
always used the string `"MEMORY_LOCATION"` — confirmed consistent everywhere else in the
tree by grep. `ProgramGraphLoader.loadSourceOriginFacts` does a strict `Enum.valueOf(...)`
on that string, so it threw `IllegalArgumentException: No enum constant
portable.graph.SourceOriginFact.TargetKind.MEMORY_LOCATION` on every fact of that shape.

**Fix (2 files, 2 lines):**
- `core/program_graph/src/main/java/portable/graph/SourceOriginFact.java`:
  enum constant `MEMORY` → `MEMORY_LOCATION`.
- `core/provenance-neutral/src/main/java/portable/provenance/PortableProvenanceEngine.java`:
  updated the one call site (`sourceOriginSummary`) that referenced `TargetKind.MEMORY`.

**Verification:** rebuilt the Java core fresh, re-ran `source-r02/run.sh` standalone —
`SOURCE_R02C2=13/13` (was 7/13) — and the full `tests/run_all.py` suite with Layer 2
enabled: no regressions in any other gate that touches `SourceOriginFact`
(`GATE 24`/`24-TS`, `CORE-S05`, `CORE-S06`, `JSTS-R05`, all `JS-STATE-*`/`JS-PROP-*`/`JS-PROV-*`).

## 2. `source-r02/run.sh` swallowed the engine crash (harness defect, fixed)

**Symptom:** the bug above was invisible as a *crash* — it surfaced only as six `[None]`
assertion failures with no indication anything had thrown.

**Root cause:** `run.sh` invoked `EndToEndRunner` as
`... > "$W/sink.out" 2>/dev/null || true`. Any crash (exit code, stack trace) was
discarded; the script always continued to the Python checker, which read an empty
`sink.out` and correctly reported "no fact" for K1/K3/K4/K5/H5/H6 — technically true, but
it hid that the real problem was an unhandled exception in the engine, not a logic gap.

**Fix:** the run now checks the exit code explicitly, keeps stderr in a file (`sink.err`),
and on failure prints the real stack trace and exits `21` instead of continuing:

```bash
if ! SINKS="sink:0" java -cp "$ROOT/tests/gates/jsts-r05/build" EndToEndRunner ... \
    > "$W/sink.out" 2>"$W/sink.err"; then
  echo "FATAL: EndToEndRunner crashed — see stderr below" >&2
  cat "$W/sink.err" >&2
  exit 21
fi
```

**Verification:** confirmed both directions —
- Unmodified engine + fixed enum: `run.sh` still exits `0`, `SOURCE_R02C2=13/13`.
- Deliberately broken classpath (`-cp /nonexistent-classpath`): `run.sh` now exits `21`
  and prints the real `ClassNotFoundException`, instead of silently reporting `[None]`.

Audited every other `2>/dev/null || true` in `tests/gates/**/run.sh` (grep, 21 hits): all
the rest guard best-effort artifact copies (`cp "$RUN/result.txt" "$HERE/run/" ...`) after
the real computation has already succeeded or already been checked — not a computation's
own exit status. Only this one site needed the fix.

## 3. `GUARD-R01` — mislabeled as a regression (harness classification fix, not a code fix)

**Not a bug in the guard logic.** Per `tests/gates/guard-r01/FIXTURE_NOTE.md`, its
`/tmp/cmp2` and `/tmp/pp2` fact documents are operator-maintained and were lost during an
earlier packaging session; no builder for them exists anywhere in this bundle. `run.sh`
itself already detects this and exits 20 with `GUARD-R01 BLOCKED: fixtures absent`.

**Problem:** `tests/run_all.py` called it unconditionally whenever `guard-r01/` and the
`jsts-r05/build` directory existed, with no pre-check for the fixtures themselves — so its
self-reported "BLOCKED" exit code 20 was caught by the generic `run()` helper and counted
as a plain `FAIL` / regression, exactly like every other "needs JOERN_HOME" gate is
pre-checked and routed to `blocked()` instead.

**Fix:** added the same fixture pre-check `run_all.py` already uses for every other
conditionally-available gate:

```python
if (G/'guard-r01').exists() and (G/'jsts-r05'/'build').exists() \
        and _pl.Path('/tmp/cmp2/program.json').exists() and _pl.Path('/tmp/pp2/program.json').exists():
    run(114,['bash','run.sh'],cwd=G/'guard-r01',name='GUARD-R01')
else:
    blocked(114,'GUARD-R01','MISSING_FIXTURES: /tmp/cmp2, /tmp/pp2 not regenerated — see FIXTURE_NOTE.md')
```

**Verification:** `GUARD-R01` now reports
`GUARD-R01 BLOCKED (MISSING_FIXTURES: /tmp/cmp2, /tmp/pp2 not regenerated — see FIXTURE_NOTE.md)`
and drops out of `REGRESSIONS` (1 → 0). It correctly still trips
`HARNESS_HEALTH=FAIL` / `expected gate(s) never reported: ['GUARD-R01', 'JSTS-R06']` —
by design (see the comment at the top of that check in `run_all.py`): a genuinely
never-executed expected gate must stay loud, it just must not be miscounted as a fresh
regression.

## Full-suite result after all three fixes (fresh sandbox, Joern v4.0.608 pinned + verified)

```
EXECUTED 42/42
REGRESSIONS 0
HARNESS_HEALTH=FAIL
  !! expected gate(s) never reported: ['GUARD-R01', 'JSTS-R06']
```

Both remaining `HARNESS_HEALTH` items are genuine, pre-existing, documented prerequisite
gaps (lost operator-maintained fixtures for `GUARD-R01`; no replay corpus for `JSTS-R06`)
— not something fixable from the contents of this bundle. Everything else, including the
newly-fixed `SOURCE-R02`, passes.

## Note on `bootstrap.sh`

The bundled `bootstrap.sh` downloads `joern-cli.zip`, which 404s — the actual pinned
release asset is `joern-cli-linux-x86_64.zip`
(`https://github.com/joernio/joern/releases/download/v4.0.608/joern-cli-linux-x86_64.zip`).
Worked around manually for this run (not patched in `bootstrap.sh` itself, since Joern is
explicitly out-of-bundle per `SETUP_AND_RUN.md`); worth fixing upstream if this script is
still relied on.
