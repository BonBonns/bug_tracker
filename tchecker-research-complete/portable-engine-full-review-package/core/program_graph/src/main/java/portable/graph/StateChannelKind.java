package portable.graph;

/** Out-of-band state families that are distinct from durable persistence. */
public enum StateChannelKind {
    REQUEST,
    SESSION,
    ENVIRONMENT,
    PROCESS
}
