package portable.effects;

import java.util.*;

/** Assessment for one parser/use-context boundary along one concrete structural path. */
public record ContextLayerAssessment(
        EffectRequirement requirement,
        List<String> operationsSincePriorBoundary,
        Adequacy adequacy,
        String reason) {
    public ContextLayerAssessment {
        requirement = Objects.requireNonNull(requirement);
        operationsSincePriorBoundary = List.copyOf(Objects.requireNonNull(operationsSincePriorBoundary));
        adequacy = Objects.requireNonNull(adequacy);
        reason = Objects.requireNonNull(reason);
    }
}
