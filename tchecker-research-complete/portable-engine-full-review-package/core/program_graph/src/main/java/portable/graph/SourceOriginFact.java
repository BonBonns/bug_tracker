package portable.graph;

/** SOURCE-R02: a frontend assertion that an operation introduced externally
 *  controlled data into a program value. Deliberately NOT knowledge of any
 *  particular API: the frontend names the origin kind, the core only propagates
 *  it. The historical targetLocalId field is also the target fact id when the
 *  target kind is STATE_READ. */
public record SourceOriginFact(
    long id,
    long functionId,
    long targetLocalId,
    TargetKind targetKind,
    String originKind,
    String location,
    FactDerivation derivation
) {
    public enum TargetKind { LOCAL, MEMORY_LOCATION, PARAMETER, STATE_READ }

    public SourceOriginFact {
        if (targetKind == null)
            throw new IllegalArgumentException("source origin must name its target kind");
        if (originKind == null || originKind.isBlank())
            throw new IllegalArgumentException("source origin must name its kind");
        if (derivation == null)
            throw new IllegalArgumentException("source origin facts must carry their derivation");
    }
}
