package portable.graph;

/** Lexical capture: an inner function's materialized binding denotes an outer
 *  function's binding. Pure binding relationship — capture never carries taint or
 *  origin by itself; provenance flows through the outer binding's own facts. */
public record CaptureFact(
    long innerFunctionId,
    long innerLocalId,
    String innerBinding,
    long outerFunctionId,
    long outerNodeId,
    String outerBinding,
    OuterKind outerKind,
    Resolution resolution,
    FactDerivation derivation
) {
    public enum OuterKind { LOCAL, PARAMETER }
    public CaptureFact {
        if (resolution == Resolution.EXACT && outerNodeId <= 0)
            throw new IllegalArgumentException("EXACT capture requires a concrete outer node");
    }
}
