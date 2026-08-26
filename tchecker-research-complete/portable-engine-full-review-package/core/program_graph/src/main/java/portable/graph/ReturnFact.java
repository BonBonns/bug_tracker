package portable.graph;

/** One return statement/expression in a function. */
public record ReturnFact(long id, long functionId, ValueRef value, Integer line) {}
