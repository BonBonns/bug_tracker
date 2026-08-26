package portable.graph;

import java.util.List;

/** Which abstract object/location a binding may denote — NOT what origin its value
 *  carries. Identity and provenance are deliberately separate: identity tokens key
 *  state locations; provenance flows only through value references. */
public record IdentityFact(
    long functionId,
    String binding,
    List<String> identities,
    boolean must,
    Resolution resolution,
    FactDerivation derivation
) {
    public IdentityFact {
        identities = List.copyOf(identities);
        if (identities.isEmpty()) throw new IllegalArgumentException("identity fact requires >=1 identity");
        if (must != (identities.size() == 1))
            throw new IllegalArgumentException("must <=> singleton identity set");
        if (must && resolution != Resolution.EXACT)
            throw new IllegalArgumentException("singleton identity must be EXACT");
        if (!must && resolution == Resolution.EXACT)
            throw new IllegalArgumentException("a MAY identity set cannot be EXACT");
    }
}
