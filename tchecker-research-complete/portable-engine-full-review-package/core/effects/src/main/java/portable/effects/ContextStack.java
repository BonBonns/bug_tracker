package portable.effects;

import java.util.*;

/**
 * Ordered parser/use-context stack for one semantic value path.
 *
 * A value may cross several interpreters before final consumption.  The stack
 * preserves that order explicitly so a transformation proven adequate for one
 * layer cannot be reused for another layer by flattened membership.
 */
public record ContextStack(List<EffectRequirement> layers) {
    public ContextStack {
        Objects.requireNonNull(layers);
        layers = List.copyOf(layers);
        if (layers.stream().anyMatch(Objects::isNull))
            throw new IllegalArgumentException("context stack layer cannot be null");
    }

    public static ContextStack of(EffectRequirement... layers) {
        return new ContextStack(List.of(layers));
    }

    public int size() { return layers.size(); }
    public boolean isEmpty() { return layers.isEmpty(); }
}
