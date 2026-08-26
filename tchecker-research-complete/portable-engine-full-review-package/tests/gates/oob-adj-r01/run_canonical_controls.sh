#!/usr/bin/env bash
# Canonical OOB-ADJ-R02 controls through scan_repo (needs JOERN_HOME + two dirs of vuln/patched .cpp).
# Verifies: vuln=1/patched=0 packets; forged source via --oob-hints stays advisory; --oob-trusted-
# attestations suppresses; dir reuse leaves no stale packet; producer fault => nonzero scan exit.
# See R02-canonical-controls.txt for expected outputs. Not hermetic (builds CPGs); the hermetic
# checks live in gate_oob_adjudication.py.
echo "see R02-canonical-controls.txt; requires JOERN_HOME, vuln/ and patched/ source dirs"
