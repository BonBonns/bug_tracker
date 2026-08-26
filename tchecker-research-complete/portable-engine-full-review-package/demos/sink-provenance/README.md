# Sink-provenance demo

"Which input does the value reaching this security-relevant operand derive from?"
Only the SINK OPERAND changes between variants; everything else is constant.

    JOERN_HOME=/path/to/joern-cli ./run.sh

## Expected output
variant                operand #1 (buffer)              operand #2 (length)
v1_attacker_operand    EXACT proven=[1]  unknown=false  UNRESOLVED unknown=true
v2_trusted_operand     EXACT proven=[2]  unknown=false  UNRESOLVED unknown=true
v3_external_buffer     UNRESOLVED        unknown=true   UNRESOLVED unknown=true
v4_internal_literal    UNRESOLVED        unknown=true   EXACT proven=[] unknown=false

## What each row demonstrates
v1 -> v2  Patching ONLY the operand moves the claimed origin from parameter 1
          (`user`) to parameter 2 (`safe`). In security terms: "the value reaching
          this write derives from attacker-controlled input" becomes "it derives
          from the trusted input", with nothing else in the function altered.
v3        The operand comes from `make_buf()`, an external function with no body
          available. The engine ABSTAINS. It does not conclude "no parameter
          origin" merely because it found no path — the distinction this project
          exists to preserve.
v4        The length operand is the literal `8`: EXACT proven=[] with
          unknown=false, a POSITIVE assertion that no parameter contributes.

## The calibration contrast, visible in one call
    EXACT proven=[] , unknown=false   ->  proven to have NO parameter origin
    UNRESOLVED      , unknown=true    ->  origin could NOT be determined
v4 shows both states in two arguments of the SAME call site.

## A detail worth noting
In v1/v2 the LENGTH operand is `strlen_(user)` / `strlen_(safe)` and abstains,
because `strlen_` is an external declaration. That is correct: the engine will not
claim the length derives from the buffer parameter without the callee's body. Only
the literal in v4 is provably source-free. This is why v1/v2 discriminate on the
buffer operand but not on the length operand.
