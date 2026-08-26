# JS-PROV-R26 RECOVERY — preregistered before fixture reconstruction

## New invariants (permanent)

```text
R26-FIXTURE-INTEGRITY:
  Every gate assertion key identifies exactly one intended semantic case.
  Duplicate local binding names across independent fixture cases are FORBIDDEN
  unless the test explicitly asserts multi-record behaviour.

R26-SET-DISJOINTNESS:
  For a given resolved fixture binding identity,
      ESTABLISHED  n  ABSTAINED  =  {}
```

## Fixture-directory rule (promoted to a standing rule)

```text
Promotion fixtures are VERSIONED EXPERIMENTAL INPUTS, not disposable scratch
files. Existing fixtures must never be overwritten by a later revision.
```

## Recovery procedure (order is binding)
1. Rebuild R26 fixtures under `r26_chain_* / r26_cycle_* / r26_mutual_* /
   r26_missing_*` namespaces. Do NOT repair the contaminated files in place.
2. Add a fixture-integrity assertion (binding-name uniqueness).
3. Recompute `ESTABLISHED n ABSTAINED` explicitly; required empty.
4. If any binding remains in both sets, TRACE both records to their exact
   fixture/module origins. **Do not rename to fix.**
5. Only then recheck Corpus B/C and consider closeout.

## Open question to answer with evidence, not narrative
Is the defect in the RESOLVER (a genuinely contradictory record) or in the
GATE'S IDENTITY KEY (coarse keying collapsing two legitimate distinct
observations that share a human-readable local name)? Either is possible; the
recovery must demonstrate which.
