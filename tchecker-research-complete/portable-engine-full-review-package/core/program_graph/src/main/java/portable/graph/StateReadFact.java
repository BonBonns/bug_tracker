package portable.graph;

/** One keyed-state read: receiver[key] (index or field accessor). */
public record StateReadFact(
    long id,
    long functionId,
    String accessor,
    ValueRef receiver,
    KeySelector key,
    Resolution resolution,
    Integer line,
    FactDerivation derivation,
    StateLocation receiverLocation
) {
    public StateReadFact {
        if (key.kind() == KeySelector.Kind.DYNAMIC && resolution == Resolution.EXACT)
            throw new IllegalArgumentException("a DYNAMIC-key read cannot be EXACT");
        if (receiverLocation == null)
            throw new IllegalArgumentException("state read requires a receiver location");
    }

    /** Backward-compatible constructor for portable-state-facts/0.3. */
    public StateReadFact(long id, long functionId, String accessor, ValueRef receiver,
                         KeySelector key, Resolution resolution, Integer line,
                         FactDerivation derivation) {
        this(id, functionId, accessor, receiver, key, resolution, line, derivation,
             StateLocation.direct(receiver));
    }
}
