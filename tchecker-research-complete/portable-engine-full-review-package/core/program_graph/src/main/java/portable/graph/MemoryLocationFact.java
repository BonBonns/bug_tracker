package portable.graph;

/** A derived memory location (struct field, constant-index element) that a C/C++
 *  frontend proved mechanically and materialized as a synthetic local. This fact
 *  makes the derivation CONTRACTUAL: the core can distinguish a real local from
 *  a derived location, see its base/selector structure, and cross-validate that
 *  every declared location corresponds to an actual local in the program doc. */
public record MemoryLocationFact(
    long id,
    long functionId,
    Kind kind,
    long baseId,
    String selector,
    String name,
    Resolution resolution,
    FactDerivation derivation
) {
    public enum Kind { FIELD, INDEX }
    public MemoryLocationFact {
        if (resolution == Resolution.EXACT) {
            if (baseId <= 0) throw new IllegalArgumentException("EXACT memory location requires a concrete base");
            if (selector == null || selector.isEmpty())
                throw new IllegalArgumentException("EXACT memory location requires a selector");
        }
        if (derivation == null) throw new IllegalArgumentException("memory locations must carry their derivation");
    }
}
