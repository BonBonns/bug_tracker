# Frozen corpus audit

Scanner commit `b704aab26e3b7872d21350816ac9d60aaf0e4d3f`. Universe: **151 distinct operations** (de-duplicated from 192 raw producer records).

> Every count below is a **scanner-emitted** state, not verified ground truth. The verified bucket and program outcome are established by a separate downstream layer.


### By analysis status

| key | count |
|-----|-------|
| abstained | 107 |
| open_candidate | 42 |
| deterministic_complete | 2 |


### By primary reason (non-deterministic)

| key | count |
|-----|-------|
| required_evidence_absent | 85 |
| write_count_bound_not_established | 30 |
| conflicting_reaching_allocations | 16 |
| capacity_relation_not_established | 12 |
| destination_identity_ambiguous | 4 |
| unknown_allocator_contract | 2 |


### By uncertainty bucket

| key | count |
|-----|-------|
| insufficient_evidence | 85 |
| relationship_unresolved | 42 |
| conflicting_definitions | 16 |
| identity_ambiguous | 4 |
| None | 2 |
| external_contract_unknown | 2 |


### By recommended route

| key | count |
|-----|-------|
| additional_evidence_required | 105 |
| semantic_relationship_review | 42 |
| None | 2 |
| semantic_contract_review | 2 |


### By LLM-eligibility

| key | count |
|-----|-------|
| False | 105 |
| True | 44 |
| None | 2 |


### By canonical producer

| key | count |
|-----|-------|
| oob_runtime_capacity_verdict | 105 |
| oob_cursor_write_verdict | 42 |
| oob_interprocedural_verdict | 4 |


### By CVE

| key | count |
|-----|-------|
| CVE-2019-11745 | 44 |
| CVE-2019-11759 | 44 |
| Debian #768369 | 30 |
| CVE-2019-17006 | 22 |
| CVE-2016-1950 | 8 |
| CVE-2021-43527 | 3 |


### By revision side

| key | count |
|-----|-------|
| vuln | 76 |
| patched | 75 |


### By source label

| key | count |
|-----|-------|
| cve-2019-11745/patched | 22 |
| cve-2019-11745/vuln | 22 |
| cve-2019-11759/patched | 22 |
| cve-2019-11759/vuln | 22 |
| mjpg-cve-huff/patched | 15 |
| mjpg-cve-huff/vuln | 15 |
| cve-2019-17006/patched | 11 |
| cve-2019-17006/vuln | 11 |
| cve-2016-1950/patched | 4 |
| cve-2016-1950/vuln | 4 |
| cve-2021-43527/vuln | 2 |
| cve-2021-43527/patched | 1 |


### De-duplication

- raw records: 192
- distinct operations: 151
- merged away (same op seen by >1 producer): 41
- genuine disagreements (flagged `dedup_conflict`): 4


Conflicts (canonical = highest evidence; alternatives retained):

- `cve-2019-11745/patched` nsc_pbe_key_gen:3949 — interprocedural:open_candidate/capacity_relation_not_established; runtime:abstained/required_evidence_absent
- `cve-2019-11745/vuln` nsc_pbe_key_gen:3949 — interprocedural:open_candidate/capacity_relation_not_established; runtime:abstained/required_evidence_absent
- `cve-2019-11759/patched` nsc_pbe_key_gen:3864 — interprocedural:open_candidate/capacity_relation_not_established; runtime:abstained/required_evidence_absent
- `cve-2019-11759/vuln` nsc_pbe_key_gen:3864 — interprocedural:open_candidate/capacity_relation_not_established; runtime:abstained/required_evidence_absent
