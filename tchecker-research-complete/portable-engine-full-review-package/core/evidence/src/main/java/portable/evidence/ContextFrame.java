package portable.evidence;

import java.util.Objects;

/** Optional downstream interpretation layer; provenance itself does not assign security meaning. */
public record ContextFrame(String layer, String context) {
    public ContextFrame {
        layer = Objects.requireNonNull(layer);
        context = Objects.requireNonNull(context);
    }
}
