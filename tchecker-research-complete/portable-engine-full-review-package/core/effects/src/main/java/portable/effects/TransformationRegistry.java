package portable.effects;

import java.util.*;

/**
 * Exact relation: operation x effect-class x context -> adequacy.
 * Absence of a relation is UNKNOWN. There is deliberately no global isSafe/isSanitizer bit.
 */
public final class TransformationRegistry {
    private record Key(String operation, EffectClass effectClass, EffectContext context) {}
    private final Map<Key, TransformationRule> rules = new LinkedHashMap<>();

    public TransformationRegistry register(TransformationRule rule) {
        Objects.requireNonNull(rule);
        Key key = new Key(rule.operation(), rule.effectClass(), rule.context());
        TransformationRule prior = rules.putIfAbsent(key, rule);
        if (prior != null && !prior.equals(rule))
            throw new IllegalArgumentException("conflicting transformation rule for " + key);
        return this;
    }

    public TransformationAssessment assess(String operation, EffectClass effectClass, EffectContext context) {
        Objects.requireNonNull(operation); Objects.requireNonNull(effectClass); Objects.requireNonNull(context);
        TransformationRule rule = rules.get(new Key(operation, effectClass, context));
        if (rule == null)
            return new TransformationAssessment(operation, effectClass, context, Adequacy.UNKNOWN,
                    "no exact operation/effect/context rule");
        String why = switch (rule.adequacy()) {
            case GUARANTEED -> "registered guarantee for exact effect/context";
            case CONDITIONAL -> "conditional: " + rule.condition();
            case INADEQUATE -> "registered inadequate for exact effect/context";
            case UNKNOWN -> "registered unknown for exact effect/context";
        };
        return new TransformationAssessment(operation, effectClass, context, rule.adequacy(), why);
    }

    public int size() { return rules.size(); }
    public List<TransformationRule> rules() { return List.copyOf(rules.values()); }
}
