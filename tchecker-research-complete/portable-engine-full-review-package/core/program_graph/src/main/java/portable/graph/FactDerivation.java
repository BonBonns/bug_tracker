package portable.graph;

import java.util.List;

/** Provenance of a derived fact: which rule produced it from which frontend nodes.
 *  Carried for audit/debug only — it must never alter provenance strength. */
public record FactDerivation(String origin, String rule, List<Long> sourceNodeIds) {
    public FactDerivation {
        if (origin == null || origin.isBlank()) throw new IllegalArgumentException("derivation origin required");
        if (rule == null || rule.isBlank()) throw new IllegalArgumentException("derivation rule required");
        sourceNodeIds = List.copyOf(sourceNodeIds);
    }
}
