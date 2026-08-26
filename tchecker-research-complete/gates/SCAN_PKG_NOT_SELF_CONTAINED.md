# NOT_SELF_CONTAINED: gates/scan_pkg.sh

Real, useful utility -- the canonical way to regenerate the 6 detector gates' fixture data from
source (builds a CPG, then runs module_export_identity.sc from Component B plus 6 producer
scripts from tchecker-property-adjudicator/producers/, all as bare relative paths).

It assumes a FLAT working directory where the Component B path and all 6 producer .sc scripts
are direct siblings (matching /home/claude/work's actual layout, where this bundle's source
material lives). This bundle's structure is NOT flat (producers/, gates/, and Component B are
separate top-level directories), so running scan_pkg.sh unmodified from gates/ will fail to find
export_guard_facts.sc etc.

Not fixed by rewriting the script (that risks silently changing behavior without
re-verification, which this session has repeatedly found necessary to actually confirm rather
than assume). Documented here instead: to use it, either run it from a temporary flat directory
assembled from tchecker-property-adjudicator/producers/*.sc + portable-engine-full-review-package/,
or treat the already-bundled gates/fixtures/*-out/raw/*.tsv as the reproducible artifact and use
scan_pkg.sh as a reference for how they were originally produced.
