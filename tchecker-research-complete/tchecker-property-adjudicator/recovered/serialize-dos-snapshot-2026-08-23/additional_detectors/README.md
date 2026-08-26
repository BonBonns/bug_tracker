# Additional producers and detector suite (earlier 5-shape work)
These are the broader TChecker producers and per-mechanism gates/builders (serialize-DoS,
denylist-bypass, global-mutation, guard-fallthrough, validation-bypass, malicious-npm, R38/39/40).
They share the CPG/fact-table architecture but each has its own harness. The verified, runnable
end-to-end in this package is the serialize-DoS security-property pipeline (see ../README.md and
../run.sh). These files are included so the full codebase is present; wiring each gate's harness is
per-mechanism and not exercised by ../run.sh.
