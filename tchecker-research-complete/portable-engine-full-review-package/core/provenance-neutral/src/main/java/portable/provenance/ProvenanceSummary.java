package portable.provenance;

import portable.graph.Resolution;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Return provenance in terms of current-function parameters plus out-of-band origins. */
public record ProvenanceSummary(
    Resolution resolution,
    Set<Integer> provenPositions,
    Set<Integer> mayPositions,
    Set<OriginRef> provenOrigins,
    Set<OriginRef> mayOrigins,
    boolean unknown,
    AnalysisCompleteness completeness,
    List<TruncationEvent> truncations
) {
    public ProvenanceSummary {
        // Set.copyOf() DISCARDS iteration order, which made printed rows
        // nondeterministic across runs; keep sorted, unmodifiable views instead so
        // conformance harnesses compare stable output.
        provenPositions = java.util.Collections.unmodifiableSet(new TreeSet<>(provenPositions));
        TreeSet<Integer> may = new TreeSet<>(mayPositions); may.removeAll(provenPositions);
        mayPositions = java.util.Collections.unmodifiableSet(may);
        provenOrigins = Set.copyOf(provenOrigins);
        java.util.HashSet<OriginRef> mo = new java.util.HashSet<>(mayOrigins); mo.removeAll(provenOrigins); mayOrigins = Set.copyOf(mo);
        truncations = List.copyOf(truncations);
        // STATUS-R03 INVARIANTS. These combinations are internally contradictory
        // and were silently constructible: `b4` in the balanced corpus reported
        // EXACT with an EMPTY proven set and may={0,1}, i.e. "exact" while nothing
        // was proven. Rejecting them makes the resolution label answerable to the
        // evidence rather than a free-standing annotation.
        // NOTE: EXACT + proven={} + may={} + unknown=false stays VALID — that is
        // the positive "analysis complete, no origins" answer.
        if (resolution == Resolution.EXACT && !mayPositions.isEmpty())
            throw new IllegalArgumentException("EXACT cannot carry may positions beyond proven: may=" + mayPositions);
        if (resolution == Resolution.EXACT && unknown)
            throw new IllegalArgumentException("EXACT cannot be unknown");
        if (resolution == Resolution.POSSIBLE_UNBOUNDED && mayPositions.isEmpty() && mayOrigins.isEmpty())
            throw new IllegalArgumentException("POSSIBLE_UNBOUNDED requires a known contribution");
        if (!truncations.isEmpty() && completeness != AnalysisCompleteness.PARTIAL)
            throw new IllegalArgumentException("truncations require PARTIAL completeness");
    }
    /** Gate-27 compatibility. */
    public ProvenanceSummary(Resolution resolution, Set<Integer> provenPositions, Set<Integer> mayPositions, boolean unknown, AnalysisCompleteness completeness, List<TruncationEvent> truncations) {
        this(resolution, provenPositions, mayPositions, Set.of(), Set.of(), unknown, completeness, truncations);
    }
    /** Gate-26 compatibility. */
    public ProvenanceSummary(Resolution resolution, Set<Integer> provenPositions, Set<Integer> mayPositions, boolean unknown) {
        this(resolution, provenPositions, mayPositions, Set.of(), Set.of(), unknown,
            unknown ? AnalysisCompleteness.UNKNOWN : AnalysisCompleteness.COMPLETE, List.of());
    }
    public static ProvenanceSummary exact(Set<Integer> proven) {
        return new ProvenanceSummary(Resolution.EXACT, proven, Set.of(), Set.of(), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of());
    }
    public static ProvenanceSummary unresolved() {
        return new ProvenanceSummary(Resolution.UNRESOLVED, Set.of(), Set.of(), Set.of(), Set.of(), true, AnalysisCompleteness.UNKNOWN, List.of());
    }
    public static ProvenanceSummary truncated(TruncationEvent event) {
        return new ProvenanceSummary(Resolution.UNRESOLVED, Set.of(), Set.of(), Set.of(), Set.of(), true, AnalysisCompleteness.PARTIAL, List.of(event));
    }
}
