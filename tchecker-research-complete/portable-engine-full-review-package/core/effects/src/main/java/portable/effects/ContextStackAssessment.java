package portable.effects;

import java.util.*;

/** Result of evaluating one ordered context stack against one structural path. */
public record ContextStackAssessment(
        ContextStack stack,
        List<ContextLayerAssessment> layers,
        Adequacy adequacy,
        boolean complete) {
    public ContextStackAssessment {
        stack = Objects.requireNonNull(stack);
        layers = List.copyOf(Objects.requireNonNull(layers));
        adequacy = Objects.requireNonNull(adequacy);
    }

    public boolean guaranteed() {
        return complete && adequacy == Adequacy.GUARANTEED;
    }
}
