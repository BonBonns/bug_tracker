package portable.graph;

/**
 * How a state-channel read obtains provenance.
 * EXTERNAL_SOURCE means the channel itself is an origin (e.g. request/environment input).
 * WRITE_LINKED means provenance must come from explicitly demonstrated writes.
 * UNMODELED means the frontend/profile knows this is a state channel but cannot model its origin yet.
 */
public enum StateChannelSourceMode {
    EXTERNAL_SOURCE,
    WRITE_LINKED,
    UNMODELED
}
