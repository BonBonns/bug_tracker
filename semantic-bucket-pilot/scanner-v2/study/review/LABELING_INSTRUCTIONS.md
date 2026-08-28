# Stage 1 labeling — reviewer instructions

You are one of two **independent** reviewers. Do not confer with the other reviewer.
Label every case in your bundle (`reviewer_N_bundle.jsonl`) by filling the `label`
object in each row. Return the completed file as `reviewer_N_labels.jsonl`.

You see a **neutral reference packet**: shared code + established scanner facts. You
do NOT see which review condition, bucket, route, or repository side a case belongs
to, and you see no model output. Judge each case on the evidence shown.

## Fill these fields per case

- `evidence_reference_conclusion`: **safe | vulnerable | unresolved** — the conclusion
  the packet evidence supports. If the evidence does not establish either outcome,
  answer **unresolved** (do not guess). This is the primary scored field.
- `established_facts_valid`: **valid | invalid | unresolved** — is the packet's stated
  capacity / write-length fact actually correct for this code? If a load-bearing fact
  is wrong, mark **invalid** (the case is then excluded as an upstream evidence
  error); if you cannot tell, **unresolved**.
- `program_outcome`: **safe | vulnerable | not_established** — your best judgment of
  the code's real status (reported separately, not scored). May differ from the
  evidence-relative conclusion.
- `relationship_answer`: **established | contradicted | unresolved** — did the packet
  establish the length/capacity relationship, contradict it, or leave it open?
- `rationale`: free text — the reasoning for your conclusion.
- `supporting_evidence`: which packet fields were load-bearing (e.g. capacity,
  write_length, guard, reachability, function_source).
- `reviewer_confidence`: **high | medium | low**.

## Rules

- Do not assume an operation is vulnerable because it "looks like" a known bug; label
  from the evidence shown.
- `unresolved` is a first-class answer; use it when the evidence is insufficient.
- Related cases share a `family_ref` and appear as `sibling_instance_ids`; you may
  compare them, but label each case on its own.
- Return every instance_id in your bundle, exactly once.

After both reviewers return files, an import validator checks completeness and
independence, and a disagreement file is produced for the frozen tie-break reviewer.
