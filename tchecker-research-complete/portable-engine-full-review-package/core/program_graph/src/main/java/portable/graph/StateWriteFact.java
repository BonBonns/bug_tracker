package portable.graph;

/** One keyed-state write: receiver[key] = value (index or field accessor). */
public record StateWriteFact(
    long id,
    long functionId,
    String accessor,
    ValueRef receiver,
    KeySelector key,
    ValueRef value,
    Resolution resolution,
    Integer line,
    FactDerivation derivation,
    StateLocation receiverLocation
) {
    public StateWriteFact {
        if (key.kind() == KeySelector.Kind.DYNAMIC && resolution == Resolution.EXACT)
            throw new IllegalArgumentException("a DYNAMIC-key write cannot be EXACT");
        if (receiverLocation == null)
            throw new IllegalArgumentException("state write requires a receiver location");
    }

    /** Backward-compatible constructor for portable-state-facts/0.3. */
    public StateWriteFact(long id, long functionId, String accessor, ValueRef receiver,
                          KeySelector key, ValueRef value, Resolution resolution,
                          Integer line, FactDerivation derivation) {
        this(id, functionId, accessor, receiver, key, value, resolution, line,
             derivation, StateLocation.direct(receiver));
    }
}
