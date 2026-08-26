package portable.graph;

import java.util.List;

/** Which memory locations a pointer binding may denote — the memory-model sibling
 *  of IdentityFact, and like it strictly separate from provenance: targets key
 *  locations; values flow only through the program's own assignments. A target
 *  set larger than one is MAY and can never claim EXACT. */
public record PointsToFact(
    long functionId,
    long pointerBindingId,
    String pointerBinding,
    List<Long> targetIds,
    boolean must,
    Resolution resolution,
    FactDerivation derivation
) {
    public PointsToFact {
        targetIds = List.copyOf(targetIds);
        if (targetIds.isEmpty()) throw new IllegalArgumentException("points-to fact requires >=1 target");
        if (must != (targetIds.size() == 1))
            throw new IllegalArgumentException("must <=> singleton target set");
        if (!must && resolution == Resolution.EXACT)
            throw new IllegalArgumentException("a MAY target set cannot be EXACT");
        if (derivation == null) throw new IllegalArgumentException("points-to facts must carry their derivation");
    }
}
