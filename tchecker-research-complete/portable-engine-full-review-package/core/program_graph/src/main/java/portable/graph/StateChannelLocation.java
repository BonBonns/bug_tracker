package portable.graph;

import java.util.Objects;

/** Language-neutral identity for non-persistence state. */
public record StateChannelLocation(
    StateChannelKind kind,
    String namespace,
    String objectIdentity,
    String slot
) {
    public StateChannelLocation {
        Objects.requireNonNull(kind);
        namespace = namespace == null ? "" : namespace;
        objectIdentity = objectIdentity == null ? "" : objectIdentity;
        slot = slot == null ? "" : slot;
    }

    public String stableKey() {
        return kind + ":" + namespace + ":" + objectIdentity + ":" + slot;
    }
}
