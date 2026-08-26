package portable.graph;

/** A demonstrated write into an out-of-band state channel. */
public record StateChannelWriteFact(
    long id,
    long functionId,
    StateChannelLocation location,
    ValueRef value,
    Integer line
) {}
