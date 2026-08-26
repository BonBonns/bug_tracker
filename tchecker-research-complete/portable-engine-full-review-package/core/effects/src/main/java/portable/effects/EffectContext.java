package portable.effects;

import java.util.Objects;

/** A use context is intentionally language/framework neutral. */
public record EffectContext(String domain, String context) {
    public EffectContext {
        domain = Objects.requireNonNull(domain).trim();
        context = Objects.requireNonNull(context).trim();
        if (domain.isEmpty() || context.isEmpty()) throw new IllegalArgumentException("context fields must be non-empty");
    }
}
