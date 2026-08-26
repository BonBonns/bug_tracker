# TChecker — setup & run (fresh sandbox)

This bundle contains the full engine, adjudicator, all gates/fixtures, and the OOB analysis +
candidate-to-review-packet pipeline (OOB-INDEX-R01, OOB-ADJ-R01..R04) with their canonical
`scan_repo` integration. It is self-contained EXCEPT for Joern (a 1.9 GB external tool), which is
only needed to (re)build CPGs from source for Layer-2 gates.

## 1. Requirements
- Python 3.10+ (Layer 1 needs nothing else).
- For Layer 2 (fresh CPG builds + OOB canonical controls): a JDK (21 used in development) and Joern
  v4.0.608. Install with:  `bash bootstrap.sh`  then  `export JOERN_HOME="$PWD/joern-install/joern-cli"`.

## 2. Run everything
```bash
unzip tchecker-research-complete-r10.zip
cd tchecker-research-complete
bash run_everything.sh            # Layer 1 (hermetic) always runs; Layer 2 runs if JOERN_HOME is set
```
- **Layer 1 (hermetic, Python only):** OOB pipeline gates (INDEX-R01, ADJ-R01/R02/R03/R04), the JS/TS
  adjudicator gates, the vulnerability-detector gates (frozen fixtures), and the portable-engine gate
  suite (stored-artifact regrades; Joern-only gates self-report BLOCKED). Runs in any fresh sandbox.
- **Layer 2 (Joern):** fresh C/C++ and JS/TS CPG-building gates (cpp-r06, cpp-param-r01, poly-r01,
  guard-r01) and the OOB canonical end-to-end controls through `scan_repo`.

## 3. The OOB pipeline (our work) — direct entry point
```bash
export JOERN_HOME=... ; export C2CPG_HEAP=2g
python3 portable-engine-full-review-package/tools/scan_repo.py <DIR_WITH_C_OR_CPP> --lang c \
        --out report.json --work /tmp/scan
# vulnerable code -> report.sides[].oob_review.packets == 1 ; patched -> 0
# --oob-hints FILE                 (UNTRUSTED advisory channel; never suppresses)
# --oob-trusted-attestations FILE  (TRUSTED channel; may suppress; fingerprint-bound, R03/R04)
```
Trust model (see tchecker-property-adjudicator/property_configs/oob_index_write.json):
identity is derived by trusted runtime (content SHA-256 of actual scanned bytes + analyzer component
hashes), never from caller labels; suppression is fingerprint-bound and recomputed from facts;
LLM answers are advisory and cannot change the deterministic verdict.

## 4. Evidence & docs
- `CHANGES_APPLIED.md` — every change we made (items 1–10).
- `docs`/`RUNBOOK.md`/`ENVIRONMENT.md`/`MANIFEST.md` — original package docs.
- MOZ-OOB-R01 baseline + canonical evidence: see the moz-pos-r01 materials referenced in
  CHANGES_APPLIED.md (pre-registration, 3-row synthesis, R02/R03/R04 canonical controls).
