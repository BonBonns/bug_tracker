package portable.graph;

/** A derived cross-language call edge: a call site in one language's frontend
 *  resolved to a function extracted by ANOTHER language's frontend (e.g. a JS
 *  native-module call to a C++ N-API function via the exports.Set binding table).
 *  The link carries full FactDerivation like every other derived fact; the core
 *  applies it only when the frontend-native resolution could not already prove
 *  the dispatch. */
public record CrossLangLinkFact(
    long callId,
    long calleeFunctionId,
    String exportName,
    Resolution resolution,
    FactDerivation derivation
) {
    public CrossLangLinkFact {
        if (resolution == Resolution.EXACT && calleeFunctionId <= 0)
            throw new IllegalArgumentException("EXACT cross-language link requires a concrete callee");
        if (derivation == null)
            throw new IllegalArgumentException("cross-language links must carry their derivation");
    }
}
