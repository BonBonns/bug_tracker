package portable.graph;

/** A demonstrated write of a semantic value into a persistence/state channel. */
public record PersistenceWriteFact(
    long id,
    long functionId,
    PersistenceLocation location,
    ValueRef value,
    Integer line
) {}
