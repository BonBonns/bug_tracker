package portable.effects;

import java.util.Objects;

/** A relation, not membership in a flat transformer/sanitizer set. */
public record TransformationRule(
        String operation,
        EffectClass effectClass,
        EffectContext context,
        Adequacy adequacy,
        String condition) {
    public TransformationRule {
        operation = Objects.requireNonNull(operation).trim();
        effectClass = Objects.requireNonNull(effectClass);
        context = Objects.requireNonNull(context);
        adequacy = Objects.requireNonNull(adequacy);
        condition = condition == null ? "" : condition.trim();
        if (operation.isEmpty()) throw new IllegalArgumentException("operation must be non-empty");
        if (adequacy == Adequacy.CONDITIONAL && condition.isEmpty())
            throw new IllegalArgumentException("conditional rules require an explicit condition");
    }
}
