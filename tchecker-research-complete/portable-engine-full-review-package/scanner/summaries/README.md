# External-library summary layer (D)

Curated, versioned semantic summaries for library/framework functions whose
bodies are NOT in the analysed source. This is CURATED KNOWLEDGE, deliberately
separate from engine inference — it exists because the three-axis analysability
measurement showed 99% of external calls are unresolvable from repo source alone
(EXTERNAL_LIBRARY_SEMANTICS boundary), reproduced in both JS/TS and C++.

## Contract (mirrors the C libc-summary contract from EXT-R01)
Each entry gives a function a return/output-provenance CLASS. Default for any
function NOT listed is OPAQUE — the engine keeps abstaining, never fabricates.

Classes:
  DATABASE_INPUT     return value is externally-authored database content
  FILE_INPUT         return value is file/stream content
  NETWORK_INPUT      return value is network content
  VALUE_PRESERVING   output provenance == a named input argument's provenance
  FRESH_ALLOCATION   returns newly allocated storage, no external origin
  PREDICATE          returns a bool/status, carries no data provenance
  OPAQUE             unknown — abstain (the default; never listed explicitly)

## Status
This is a KNOWLEDGE FILE, not an engine change. The scanner passes it to the
engine as an extra document (--summary-lib). An engine build that does not yet
consume the portable-library-summary schema treats it as inert, so shipping the
file is forward-compatible and violates no freeze.
Wiring the engine to CONSUME these summaries is a separate, gated milestone with
its own negative controls (an OPAQUE default must still abstain; a VALUE_PRESERVING
entry must not manufacture EXACT). NOT done here.
