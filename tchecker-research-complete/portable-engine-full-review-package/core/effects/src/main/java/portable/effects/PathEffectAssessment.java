package portable.effects;

import java.util.*;

/** One source-to-sink structural path. */
public record PathEffectAssessment(
        List<String> structuralSteps,
        List<ContextLayerAssessment> layers,
        Adequacy adequacy) {
    public PathEffectAssessment {
        structuralSteps = List.copyOf(Objects.requireNonNull(structuralSteps));
        layers = List.copyOf(Objects.requireNonNull(layers));
        adequacy = Objects.requireNonNull(adequacy);
    }
}
