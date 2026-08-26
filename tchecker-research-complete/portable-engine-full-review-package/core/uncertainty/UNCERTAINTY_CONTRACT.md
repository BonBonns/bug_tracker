# Uncertain Provenance Contract

Hard and uncertain provenance are separate channels.

- `returnTaintPositions`: proven/exact parameter contributions.
- `returnMayTaintPositions` + `returnMayTaintResolution`: MAY/UNKNOWN contributions.

Uncertain evidence may be rendered, traced, and propagated, but it must never be
upgraded to a hard source merely because an exact wrapper surrounds it.
