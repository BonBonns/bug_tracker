package portable.provenance;

public record TruncationEvent(
    Kind kind,
    long functionId,
    int depth,
    long workConsumed,
    String detail
) {
    public enum Kind { WORK_BUDGET, DEPTH_BUDGET }
}
