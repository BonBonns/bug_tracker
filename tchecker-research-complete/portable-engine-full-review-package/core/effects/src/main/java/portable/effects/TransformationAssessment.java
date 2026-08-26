package portable.effects;

import java.util.Objects;

public record TransformationAssessment(
        String operation,
        EffectClass effectClass,
        EffectContext context,
        Adequacy adequacy,
        String reason) {
    public TransformationAssessment {
        operation = Objects.requireNonNull(operation);
        effectClass = Objects.requireNonNull(effectClass);
        context = Objects.requireNonNull(context);
        adequacy = Objects.requireNonNull(adequacy);
        reason = Objects.requireNonNull(reason);
    }

    public boolean guaranteed() { return adequacy == Adequacy.GUARANTEED; }
}
