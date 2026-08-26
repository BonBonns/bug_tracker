package portable.effects;

import java.util.Objects;

/** A semantic effect that must hold when a value crosses a specific use/parser context. */
public record EffectRequirement(EffectClass effectClass, EffectContext context) {
    public EffectRequirement {
        effectClass = Objects.requireNonNull(effectClass);
        context = Objects.requireNonNull(context);
    }
}
