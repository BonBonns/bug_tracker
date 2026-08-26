package portable.provenance;

/**
 * Global analysis work budget. maxDepth is a high emergency guard, not the primary
 * precision control; hitting either limit is reported explicitly as truncation.
 */
public record AnalysisBudget(long maxWorkItems, int maxDepth) {
    public static final AnalysisBudget DEFAULT = new AnalysisBudget(100_000L, 256);

    public AnalysisBudget {
        if (maxWorkItems < 1) throw new IllegalArgumentException("maxWorkItems must be >= 1");
        if (maxDepth < 1) throw new IllegalArgumentException("maxDepth must be >= 1");
    }
}
